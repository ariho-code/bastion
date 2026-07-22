# ---- build stage ----
FROM golang:1.26-alpine AS build
WORKDIR /src

# Module files first for better layer caching (no external deps yet).
COPY go.mod ./
RUN go mod download

COPY . .
# Static, stripped binary.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/engine ./cmd/server

# ---- runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/engine /engine

# Render sets $PORT; the app reads it. Documented default:
ENV PORT=8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/engine"]
