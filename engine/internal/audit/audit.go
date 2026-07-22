// Package audit provides a tamper-evident, hash-chained audit log for the
// engine. Every security-relevant event (scans, auth decisions) becomes an
// immutable Entry whose hash commits to the previous entry's hash — so any
// insertion, deletion or edit anywhere in the history breaks the chain and is
// detectable. Entries are emitted as one JSON object per line (SIEM-friendly for
// Splunk/Datadog ingestion) and can be rendered as RFC 5424 syslog.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Genesis is the synthetic previous-hash of the very first entry: 64 hex zeros.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Severity mirrors the RFC 5424 numerical severities used in audit entries.
type Severity int

const (
	SevAlert   Severity = 1 // action must be taken immediately
	SevError   Severity = 3 // error / failure
	SevWarning Severity = 4 // denied / suspicious
	SevNotice  Severity = 5 // normal but significant (default for audit)
	SevInfo    Severity = 6
)

// facilityLogAudit is RFC 5424 facility 13 ("log audit") — exactly what this is.
const facilityLogAudit = 13

// Record is the caller-supplied content of an audit event. The chain fields
// (Seq, Time, PrevHash, Hash) are filled in by the log at append time.
type Record struct {
	Event     string         // stable event name, e.g. "scan", "auth.denied"
	Action    string         // what was attempted, e.g. "POST /v1/scan"
	Outcome   string         // "success" | "failure" | "denied"
	Actor     string         // key id or "anonymous"
	Tenant    string         // tenant id, when multi-tenant
	Tier      string         // plan tier
	SourceIP  string         // client IP
	RequestID string         // correlation id
	Target    string         // scan target / affected resource
	Severity  Severity       // RFC 5424 severity
	Metadata  map[string]any // additional structured context
}

// Entry is a sealed, hash-chained audit record.
type Entry struct {
	Seq       uint64         `json:"seq"`
	Time      string         `json:"ts"`
	Event     string         `json:"event"`
	Action    string         `json:"action,omitempty"`
	Outcome   string         `json:"outcome,omitempty"`
	Actor     string         `json:"actor,omitempty"`
	Tenant    string         `json:"tenant,omitempty"`
	Tier      string         `json:"tier,omitempty"`
	SourceIP  string         `json:"src_ip,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
	Target    string         `json:"target,omitempty"`
	Severity  Severity       `json:"severity"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	PrevHash  string         `json:"prev_hash"`
	Hash      string         `json:"hash"`
}

// Log is a concurrency-safe, append-only hash chain. It streams every entry to
// an io.Writer and keeps the most recent entries in a bounded ring for
// verification and admin inspection.
type Log struct {
	mu       sync.Mutex
	seq      uint64
	prevHash string
	w        io.Writer
	host     string
	appName  string
	ring     []Entry
	ringCap  int
}

// New creates a Log that streams JSON lines to w. hostname/appName appear in the
// RFC 5424 rendering. ringCap bounds the in-memory history (<=0 uses 1024).
func New(w io.Writer, hostname, appName string, ringCap int) *Log {
	if ringCap <= 0 {
		ringCap = 1024
	}
	return &Log{
		w:        w,
		host:     nonEmpty(hostname, "-"),
		appName:  nonEmpty(appName, "bastionscan"),
		prevHash: Genesis,
		ringCap:  ringCap,
	}
}

// Append seals a record into the chain and returns the resulting entry. It never
// blocks on the writer for long: a write error is swallowed (the in-memory chain
// remains authoritative), so auditing can never take down a request path.
func (l *Log) Append(rec Record) Entry {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	e := Entry{
		Seq:       l.seq,
		Time:      time.Now().UTC().Format(time.RFC3339Nano),
		Event:     rec.Event,
		Action:    rec.Action,
		Outcome:   rec.Outcome,
		Actor:     rec.Actor,
		Tenant:    rec.Tenant,
		Tier:      rec.Tier,
		SourceIP:  rec.SourceIP,
		RequestID: rec.RequestID,
		Target:    rec.Target,
		Severity:  defaultSeverity(rec.Severity),
		Metadata:  rec.Metadata,
		PrevHash:  l.prevHash,
	}
	e.Hash = hashEntry(e)
	l.prevHash = e.Hash

	if l.w != nil {
		if b, err := json.Marshal(e); err == nil {
			b = append(b, '\n')
			_, _ = l.w.Write(b)
		}
	}

	l.ring = append(l.ring, e)
	if len(l.ring) > l.ringCap {
		l.ring = l.ring[len(l.ring)-l.ringCap:]
	}
	return e
}

// Head returns the current sequence number and chain-head hash. Publishing this
// hash externally (e.g. to a WORM store) lets an auditor detect tampering of the
// entire prior history.
func (l *Log) Head() (uint64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq, l.prevHash
}

// Recent returns up to n most-recent entries (all, if n<=0), newest last.
func (l *Log) Recent(n int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.ring) {
		n = len(l.ring)
	}
	out := make([]Entry, n)
	copy(out, l.ring[len(l.ring)-n:])
	return out
}

// Verify checks the internal consistency of the retained (ring) history: every
// entry's hash must recompute, and each entry must link to its predecessor. It
// returns false and the sequence number of the first broken entry. The earliest
// retained entry's PrevHash cannot be checked against an evicted predecessor, so
// only its hash recomputation is verified.
func (l *Log) Verify() (bool, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, e := range l.ring {
		if hashEntry(e) != e.Hash {
			return false, e.Seq
		}
		if i > 0 && e.PrevHash != l.ring[i-1].Hash {
			return false, e.Seq
		}
	}
	return true, 0
}

// VerifyChain validates a full slice of entries against a known starting hash
// (use Genesis for a from-the-beginning chain). It is a pure helper for callers
// that persist the complete log elsewhere.
func VerifyChain(entries []Entry, startPrev string) (bool, uint64) {
	prev := startPrev
	for _, e := range entries {
		if e.PrevHash != prev {
			return false, e.Seq
		}
		if hashEntry(e) != e.Hash {
			return false, e.Seq
		}
		prev = e.Hash
	}
	return true, 0
}

// RFC5424 renders an entry as an RFC 5424 syslog line (facility "log audit").
func (l *Log) RFC5424(e Entry) string {
	pri := facilityLogAudit*8 + int(e.Severity)
	msgID := nonEmpty(e.Event, "-")
	procID := "-"
	sd := fmt.Sprintf(
		`[bastionscan@47714 seq="%d" hash="%s" prevHash="%s" outcome="%s" actor="%s" srcIP="%s" requestID="%s" target=%q]`,
		e.Seq, e.Hash, e.PrevHash, sdEscape(e.Outcome), sdEscape(e.Actor),
		sdEscape(e.SourceIP), sdEscape(e.RequestID), e.Target,
	)
	msg := e.Action
	if e.Target != "" {
		msg = strings.TrimSpace(e.Action + " " + e.Target)
	}
	return fmt.Sprintf("<%d>1 %s %s %s %s %s %s %s",
		pri, e.Time, l.host, l.appName, procID, msgID, sd, msg)
}

// hashEntry computes sha256 over the entry with its Hash field cleared. Struct
// field order is stable and json sorts map keys, so this is deterministic.
func hashEntry(e Entry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func defaultSeverity(s Severity) Severity {
	if s == 0 {
		return SevNotice
	}
	return s
}

func nonEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// sdEscape escapes the characters RFC 5424 reserves inside structured-data
// param values: '"', '\' and ']'.
func sdEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)
	return r.Replace(s)
}
