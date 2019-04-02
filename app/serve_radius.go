package app

import (
	"context"
)

func ServeRADIUS(ctx context.Context, sharedSecret, redis string) error {
	radiusServer := &RADIUSServer{
		SharedSecret: []byte(sharedSecret),
		CredentialProvider: &RedisCredentialProvider{
			Redis: redis,
		},
	}
	if err := radiusServer.Start(); err != nil {
		return err
	}

	<-ctx.Done()
	radiusServer.Stop()
	return ctx.Err()
}
