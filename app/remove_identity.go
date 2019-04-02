package app

import (
	"fmt"
	"strings"

	"github.com/go-redis/redis"
	"github.com/pkg/errors"
)

func RemoveIdentity(redisAddr, name string) error {
	client := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	if strings.ContainsRune(name, ':') {
		return fmt.Errorf("invalid name")
	}
	_, err := client.Del("identity:" + name + ":credentials").Result()
	return errors.Wrapf(err, "unable to remove credentials")
}
