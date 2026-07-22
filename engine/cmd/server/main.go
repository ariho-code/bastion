// Command server is the Bastionscan scanning engine — a concurrent, plugin-based
// security scanner exposed over HTTP.
//
// Scanner modules self-register via blank imports below; adding a capability
// means adding a package and one import line, never editing a central switch.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/api"
	"github.com/ariho-code/bastionscan/engine/internal/config"
	"github.com/ariho-code/bastionscan/engine/internal/scan"

	// Scanner modules — imported for their init()-time registration.
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/authweak"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/content"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/cookies"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/cors"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/csrf"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/discovery"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/dns"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/exposure"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/fingerprint"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/graphql"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/headers"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/inject"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/intel"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/jwtcheck"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/methods"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/openredirect"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/phishing"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/ports"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/resilience"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/sqli"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/subdomains"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/tls"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/vertical"
	_ "github.com/ariho-code/bastionscan/engine/internal/modules/xss"
)

func main() {
	// Structured JSON logging: each line is a self-contained JSON object with
	// its own timestamp, so no stdlib prefix.
	log.SetFlags(0)
	cfg := config.Load()

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           api.NewServer(cfg).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf(`{"level":"info","msg":"listening","version":%q,"port":%q,"modules":%d}`,
			scan.EngineVersion, cfg.Port, len(scan.Modules()))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf(`{"level":"fatal","msg":"server error","err":%q}`, err.Error())
		}
	}()

	// Graceful shutdown on SIGINT/SIGTERM.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println(`{"level":"info","msg":"shutting down"}`)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf(`{"level":"warn","msg":"graceful shutdown failed","err":%q}`, err.Error())
	}
}
