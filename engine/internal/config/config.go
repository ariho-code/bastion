// Package config loads engine settings from the environment. Everything is
// env-driven with safe defaults — no operational values are hardcoded, so the
// same binary runs in local dev and on Render without edits.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all tunable engine settings.
type Config struct {
	Port           string
	AllowedOrigins []string      // CORS allowlist; "*" allows any
	AllowPrivate   bool          // let the SSRF guard reach private hosts (dev only)
	MaxConcurrency int           // parallel modules per scan
	ModuleTimeout  time.Duration // per-module deadline
	ScanTimeout    time.Duration // whole-scan deadline
	RateLimitRPM   int           // requests per minute per client IP (0 = off)
	MaxCipherTests int           // cap on TLS cipher probes per scan
}

// Load reads configuration from the environment, applying defaults.
func Load() Config {
	return Config{
		Port:           env("PORT", "8080"),
		AllowedOrigins: splitCSV(env("ALLOWED_ORIGINS", "*")),
		AllowPrivate:   envBool("ALLOW_PRIVATE", false),
		MaxConcurrency: envInt("MAX_CONCURRENCY", 8),
		ModuleTimeout:  envDur("MODULE_TIMEOUT", 20*time.Second),
		ScanTimeout:    envDur("SCAN_TIMEOUT", 60*time.Second),
		RateLimitRPM:   envInt("RATE_LIMIT_RPM", 60),
		MaxCipherTests: envInt("MAX_CIPHER_TESTS", 40),
	}
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(env(key, "")); err == nil {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	if v, err := strconv.ParseBool(env(key, "")); err == nil {
		return v
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(env(key, "")); err == nil {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
