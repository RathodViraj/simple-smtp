package middleware

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/redis/go-redis/v9"
)

type RateLimiter struct {
	rdb       *redis.Client
	IPLimit   int64
	UserLimit int64
	duration  time.Duration
}

func NewRateLimit(rdb *redis.Client, ip, user int64, d time.Duration) *RateLimiter {
	return &RateLimiter{
		rdb:       rdb,
		IPLimit:   ip,
		UserLimit: user,
		duration:  d,
	}
}

func (r *RateLimiter) Validate(userName string, ip net.IP) bool {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
	defer cancel()

	ipKey := fmt.Sprintf("auth:ip:%s", ip)
	userKey := fmt.Sprintf("auth:user:%s", userName)

	ipCount, _ := r.rdb.Incr(ctx, ipKey).Result()
	userCount, _ := r.rdb.Incr(ctx, userKey).Result()

	if ipCount == 1 {
		r.rdb.Expire(ctx, ipKey, r.duration)
	}
	if userCount == 1 {
		r.rdb.Expire(ctx, userKey, r.duration)
	}

	return !(ipCount > r.IPLimit || userCount > r.UserLimit)
}
