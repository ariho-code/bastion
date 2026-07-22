package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func newTestLog() (*Log, *bytes.Buffer) {
	var buf bytes.Buffer
	return New(&buf, "host-1", "bastionscan-engine", 100), &buf
}

func TestAppendChainsAndStreams(t *testing.T) {
	l, buf := newTestLog()
	e1 := l.Append(Record{Event: "scan", Action: "POST /v1/scan", Outcome: "success", Target: "example.com"})
	e2 := l.Append(Record{Event: "scan", Action: "POST /v1/scan", Outcome: "success", Target: "test.com"})

	if e1.Seq != 1 || e2.Seq != 2 {
		t.Fatalf("seq not monotonic: %d, %d", e1.Seq, e2.Seq)
	}
	if e1.PrevHash != Genesis {
		t.Errorf("first entry must chain to genesis, got %s", e1.PrevHash)
	}
	if e2.PrevHash != e1.Hash {
		t.Errorf("entry 2 must chain to entry 1: prev=%s hash1=%s", e2.PrevHash, e1.Hash)
	}
	if e1.Hash == e2.Hash {
		t.Error("distinct entries must have distinct hashes")
	}
	// Each Append writes exactly one JSON line.
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 streamed lines, got %d", len(lines))
	}
	var parsed Entry
	if err := json.Unmarshal([]byte(lines[0]), &parsed); err != nil {
		t.Fatalf("streamed line is not valid JSON: %v", err)
	}
	if parsed.Hash != e1.Hash {
		t.Error("streamed hash must match returned entry")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	l, _ := newTestLog()
	for i := 0; i < 5; i++ {
		l.Append(Record{Event: "scan", Outcome: "success", Target: "site"})
	}
	if ok, _ := l.Verify(); !ok {
		t.Fatal("clean chain should verify")
	}

	// Tamper with a retained entry's content without recomputing its hash.
	l.mu.Lock()
	l.ring[2].Outcome = "failure"
	l.mu.Unlock()

	ok, brokenAt := l.Verify()
	if ok {
		t.Fatal("tampered chain must fail verification")
	}
	if brokenAt != 3 { // seq of ring[2]
		t.Errorf("expected break at seq 3, got %d", brokenAt)
	}
}

func TestVerifyDetectsDeletion(t *testing.T) {
	l, _ := newTestLog()
	var entries []Entry
	for i := 0; i < 5; i++ {
		entries = append(entries, l.Append(Record{Event: "e", Target: "t"}))
	}
	// Full-chain verification from genesis passes.
	if ok, _ := VerifyChain(entries, Genesis); !ok {
		t.Fatal("full chain should verify from genesis")
	}
	// Remove the middle entry — the link from 4 -> (was 3) is now broken.
	spliced := append(append([]Entry{}, entries[:2]...), entries[3:]...)
	if ok, brokenAt := VerifyChain(spliced, Genesis); ok || brokenAt != entries[3].Seq {
		t.Errorf("deletion must break the chain at seq %d, got ok=%v at=%d", entries[3].Seq, ok, brokenAt)
	}
}

func TestHeadAdvances(t *testing.T) {
	l, _ := newTestLog()
	if seq, h := l.Head(); seq != 0 || h != Genesis {
		t.Errorf("fresh log head should be (0, genesis), got (%d, %s)", seq, h)
	}
	last := l.Append(Record{Event: "e"})
	seq, h := l.Head()
	if seq != 1 || h != last.Hash {
		t.Errorf("head should track last entry, got (%d, %s)", seq, h)
	}
}

func TestRingEvictionKeepsRecent(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, "h", "a", 3)
	for i := 0; i < 6; i++ {
		l.Append(Record{Event: "e", Target: "t"})
	}
	recent := l.Recent(0)
	if len(recent) != 3 {
		t.Fatalf("ring should retain 3 entries, got %d", len(recent))
	}
	if recent[len(recent)-1].Seq != 6 {
		t.Errorf("most recent entry should be seq 6, got %d", recent[len(recent)-1].Seq)
	}
	// The retained window must still verify internally.
	if ok, _ := l.Verify(); !ok {
		t.Error("retained window should verify")
	}
}

func TestRFC5424Format(t *testing.T) {
	l, _ := newTestLog()
	e := l.Append(Record{
		Event: "scan", Action: "POST /v1/scan", Outcome: "success",
		Actor: "key_abcdef…", SourceIP: "203.0.113.5", RequestID: "req-1",
		Target: "example.com", Severity: SevNotice,
	})
	line := l.RFC5424(e)
	// <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID SD MSG
	if !strings.HasPrefix(line, "<109>1 ") { // 13*8 + 5 = 109
		t.Errorf("bad PRI/version prefix: %q", line)
	}
	if !strings.Contains(line, "host-1 bastionscan-engine") {
		t.Errorf("missing host/app: %q", line)
	}
	if !strings.Contains(line, `seq="1"`) || !strings.Contains(line, "hash=") {
		t.Errorf("missing structured data: %q", line)
	}
	if !strings.Contains(line, "example.com") {
		t.Errorf("missing target in message: %q", line)
	}
}
