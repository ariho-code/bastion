package scan

import (
	"net"
	"net/http"
)

// Env carries shared, safety-vetted dependencies into every module so modules
// never build their own (potentially unsafe) network clients. The engine
// constructs one Env per scan and passes it to each module's Run.
type Env struct {
	// HTTP is an SSRF-guarded client: it re-validates the resolved IP before
	// connecting and caps redirects. Modules that fetch content use this.
	HTTP *http.Client
	// Resolver performs DNS lookups (safe to share).
	Resolver *net.Resolver
	// UserAgent is the identifying UA string modules should send.
	UserAgent string
}

// DefaultEnv returns an Env with stdlib defaults — handy for tests. Production
// callers build an Env with an SSRF-guarded client (see netutil.Guard).
func DefaultEnv() *Env {
	return &Env{
		HTTP:      http.DefaultClient,
		Resolver:  net.DefaultResolver,
		UserAgent: "BastionscanEngine/" + EngineVersion,
	}
}
