package ratelimit

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RateLimiter struct {
	rdb      *redis.Client
	limit    int
	duration time.Duration
}

func NewRateLimit(rdb *redis.Client, l int, d time.Duration) *RateLimiter {
	return &RateLimiter{
		rdb:      rdb,
		limit:    l,
		duration: d,
	}
}

func (r *RateLimiter) Validate(userName string) bool {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
	defer cancel()

	key := "auth:username:" + userName

	cnt, err := r.rdb.Incr(context.Background(), key).Result()
	if err != nil {
		return false
	}

	if cnt == 1 {
		err = r.rdb.Expire(ctx, key, r.duration).Err()
		if err != nil {
			return false
		}
	}

	return cnt <= int64(r.limit)
}
