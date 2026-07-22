package api

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var openapiSpec []byte

// handleOpenAPI serves the engine's machine-readable OpenAPI 3.1 spec so the
// API is self-documenting and importable into Postman/Swagger/codegen tools.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(openapiSpec)
}
