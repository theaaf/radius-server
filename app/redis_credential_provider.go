package app

import (
	"strings"
	"sync"

	"github.com/go-redis/redis"
)

type RedisCredentialProvider struct {
	Redis string

	initClient sync.Once
	client     *redis.Client
}

func (p *RedisCredentialProvider) ensureClient() *redis.Client {
	p.initClient.Do(func() {
		p.client = redis.NewClient(&redis.Options{
			Addr: p.Redis,
		})
	})
	return p.client
}

func (p *RedisCredentialProvider) CredentialsForIdentity(id string) (EAPCredentials, error) {
	if strings.ContainsRune(id, ':') {
		return nil, nil
	}
	client := p.ensureClient()
	v, err := client.Get("identity:" + id + ":credentials").Result()
	if err == redis.Nil {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return plaintextCredential(v), nil
}

type plaintextCredential []byte

func (p plaintextCredential) PlaintextPassword() []byte {
	return []byte(p)
}
