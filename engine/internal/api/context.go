package api

import (
	"context"

	"github.com/ariho-code/bastionscan/engine/internal/auth"
)

type ctxKey int

const (
	ctxRequestID ctxKey = iota
	ctxIdentity
)

func withRequestIDValue(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxRequestID, id)
}

func requestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ctxRequestID).(string); ok {
		return v
	}
	return ""
}

func withIdentity(ctx context.Context, id auth.Identity) context.Context {
	return context.WithValue(ctx, ctxIdentity, id)
}

func identityFrom(ctx context.Context) auth.Identity {
	if v, ok := ctx.Value(ctxIdentity).(auth.Identity); ok {
		return v
	}
	return auth.Identity{Tier: auth.TierAnonymous}
}
