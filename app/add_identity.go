package app

import (
	"fmt"
	"strings"

	"github.com/go-redis/redis"
	"github.com/pkg/errors"
)

func AddIdentity(redisAddr, name, password string) error {
	client := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	if strings.ContainsRune(name, ':') {
		return fmt.Errorf("invalid name")
	}
	_, err := client.SetNX("identity:"+name+":credentials", password, 0).Result()
	return errors.Wrapf(err, "unable to store credentials")
}
