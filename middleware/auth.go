package middleware

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Auth struct {
	rdb          *redis.Client
	failLimit    int
	lockDuration time.Duration
}

func SetupAuth(rdb *redis.Client, l int, d time.Duration) *Auth {
	return &Auth{
		rdb:          rdb,
		failLimit:    l,
		lockDuration: d,
	}
}

func (a *Auth) IncreaseFails(username string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(3*time.Second))
	defer cancel()

	failKey := fmt.Sprintf("auth:fail:user:%s", username)

	fails, _ := a.rdb.Incr(ctx, failKey).Result()

	if fails == 1 {
		a.rdb.Expire(ctx, failKey, 10*time.Minute)
	}
	if fails < 5 {
		return
	}

	lockKey := fmt.Sprintf("lock:user:%s", username)
	d := a.lockDuration
	if fails >= 15 {
		d *= 6
	} else if fails >= 10 {
		d *= 3
	}

	a.rdb.Set(ctx, lockKey, "1", d)
}

func (a *Auth) CheckLock(username string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(3*time.Second))
	defer cancel()

	lockKey := fmt.Sprintf("lock:user:%s", username)
	locked, _ := a.rdb.Exists(ctx, lockKey).Result()

	return locked == 1
}
