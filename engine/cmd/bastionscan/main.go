// Command bastionscan is the enterprise CLI for ownership-gated Active AppSec.
//
//	bastionscan verify example.com
//	bastionscan active example.com --exclude /billing --disable authweak
//	bastionscan deep example.com
//
// Point at a running engine with BASTION_ENGINE_URL (default http://127.0.0.1:8080).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	base := strings.TrimRight(env("BASTION_ENGINE_URL", "http://127.0.0.1:8080"), "/")

	switch cmd {
	case "verify":
		runVerify(base, args)
	case "active", "deep", "standard", "scan":
		profile := cmd
		if cmd == "scan" {
			profile = "deep"
		}
		runScan(base, profile, args)
	case "modules":
		runModules(base)
	case "version", "-v", "--version":
		fmt.Println("bastionscan-cli 0.3.0")
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `bastionscan — enterprise ownership-gated security CLI

Usage:
  bastionscan verify <domain>
  bastionscan active <domain> [flags]
  bastionscan deep <domain>
  bastionscan modules
  bastionscan version

Active flags:
  --exclude PATH       Exclude path prefix (repeatable)
  --include PATH       Include-only path prefix (repeatable)
  --disable MODULE     Disable module id (repeatable: sqli,xss,authweak,…)
  --enable MODULE      Allow-list module id (repeatable)
  --max-requests N     Cap speculative Active HTTP requests (default 400)
  --delay MS           Delay between probes (default 25)
  --no-safe            Disable SafeMode (not recommended)

Env:
  BASTION_ENGINE_URL   Engine base URL (default http://127.0.0.1:8080)
  BASTION_API_KEY      Optional API key header
`)
}

func runVerify(base string, args []string) {
	if len(args) < 1 {
		fatal("usage: bastionscan verify <domain>")
	}
	target := args[0]
	resp, err := httpGet(base + "/v1/verify?target=" + urlQuery(target))
	if err != nil {
		fatal(err.Error())
	}
	var out map[string]any
	_ = json.Unmarshal(resp, &out)
	fmt.Printf("Domain:  %v\n", out["domain"])
	fmt.Printf("Type:    TXT\n")
	fmt.Printf("Record:  %v\n", out["record"])
	fmt.Printf("\n%v\n", out["instruction"])
}

func runScan(base, profile string, args []string) {
	fs := flag.NewFlagSet(profile, flag.ExitOnError)
	var excludes, includes, disables, enables multiFlag
	maxReq := fs.Int("max-requests", 400, "max speculative requests")
	delay := fs.Int("delay", 25, "probe delay ms")
	noSafe := fs.Bool("no-safe", false, "disable safe mode")
	fs.Var(&excludes, "exclude", "exclude path")
	fs.Var(&includes, "include", "include path")
	fs.Var(&disables, "disable", "disable module")
	fs.Var(&enables, "enable", "enable module")
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) < 1 {
		fatal("usage: bastionscan " + profile + " <domain> [flags]")
	}
	target := rest[0]
	safe := !*noSafe
	body := map[string]any{
		"target":  target,
		"profile": profile,
		"scope": map[string]any{
			"excludePaths":   []string(excludes),
			"includePaths":   []string(includes),
			"disableModules": []string(disables),
			"enableModules":  []string(enables),
			"maxRequests":    *maxReq,
			"requestDelayMs": *delay,
			"safeMode":       safe,
		},
	}
	raw, err := httpPostJSON(base+"/v1/scan", body)
	if err != nil {
		fatal(err.Error())
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("Target:    %v\n", result["host"])
	fmt.Printf("Profile:   %v\n", result["profile"])
	fmt.Printf("Verified:  %v\n", result["verified"])
	fmt.Printf("Grade:     %v  Score: %v\n", result["grade"], result["score"])
	fmt.Printf("Duration:  %vms\n", result["durationMs"])

	// Print Active category fails first.
	findings, _ := result["findings"].([]any)
	var fails int
	for _, f := range findings {
		fm, ok := f.(map[string]any)
		if !ok {
			continue
		}
		if fm["status"] != "fail" {
			continue
		}
		fails++
		fmt.Printf("\n[FAIL] %v\n  %v\n", fm["title"], fm["detail"])
		if ev, ok := fm["evidence"].(string); ok && ev != "" {
			fmt.Printf("  evidence: %s\n", trunc(ev, 240))
		}
	}
	if fails == 0 {
		fmt.Println("\nNo failing findings.")
	} else {
		fmt.Printf("\n%d failing finding(s).\n", fails)
	}
}

func runModules(base string) {
	raw, err := httpGet(base + "/v1/modules")
	if err != nil {
		fatal(err.Error())
	}
	fmt.Println(string(raw))
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func httpGet(u string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if k := os.Getenv("BASTION_API_KEY"); k != "" {
		req.Header.Set("Authorization", "Bearer "+k)
		req.Header.Set("X-API-Key", k)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, trunc(string(b), 300))
	}
	return b, nil
}

func httpPostJSON(u string, body any) ([]byte, error) {
	payload, _ := json.Marshal(body)
	client := &http.Client{Timeout: 120 * time.Second}
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if k := os.Getenv("BASTION_API_KEY"); k != "" {
		req.Header.Set("Authorization", "Bearer "+k)
		req.Header.Set("X-API-Key", k)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, trunc(string(b), 300))
	}
	return b, nil
}

func urlQuery(s string) string {
	return strings.ReplaceAll(s, " ", "%20")
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
