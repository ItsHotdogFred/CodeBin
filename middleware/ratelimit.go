package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

var (
	requestCounts sync.Map
	ipMutexes     sync.Map
)

func RateLimit(requestsPerMinute int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getClientIP(r)

			if !isAllowed(ip, requestsPerMinute) {
				http.Error(w, "Rate limit exceeded. Too many requests.", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return forwarded
	}

	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	return r.RemoteAddr
}

func isAllowed(ip string, limit int) bool {
	mtxIface, _ := ipMutexes.LoadOrStore(ip, &sync.Mutex{})
	mtx := mtxIface.(*sync.Mutex)
	mtx.Lock()
	defer mtx.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Minute)

	var validRequests []time.Time
	if reqIface, ok := requestCounts.Load(ip); ok {
		if requests, ok := reqIface.([]time.Time); ok {
			for _, reqTime := range requests {
				if reqTime.After(cutoff) {
					validRequests = append(validRequests, reqTime)
				}
			}
		}
	}

	if len(validRequests) == 0 {
		requestCounts.Delete(ip)
		ipMutexes.Delete(ip)
	}

	if len(validRequests) >= limit {
		requestCounts.Store(ip, validRequests)
		return false
	}

	validRequests = append(validRequests, now)
	requestCounts.Store(ip, validRequests)

	fmt.Printf("Rate limit check for %s: %d/%d requests in last minute\n", ip, len(validRequests), limit)
	return true
}
