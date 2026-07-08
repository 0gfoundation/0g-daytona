// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

// 0G patch: tests for the per-port public allowlist gate.

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	common_cache "github.com/daytonaio/common-go/pkg/cache"
	"github.com/daytonaio/proxy/cmd/proxy/config"
)

func newPortsTestProxy(t *testing.T, apiHandler http.HandlerFunc) *Proxy {
	t.Helper()
	srv := httptest.NewServer(apiHandler)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	return &Proxy{
		config: &config.Config{
			DaytonaApiUrl: srv.URL,
			ProxyApiKey:   "test-proxy-key",
		},
		userAPIHTTPClient:       &http.Client{Timeout: 5 * time.Second},
		sandboxPublicPortsCache: common_cache.NewMapCache[publicPortsInfo](ctx),
	}
}

func TestIsPortPubliclyAllowed_RestrictedList(t *testing.T) {
	p := newPortsTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-proxy-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"publicPorts":[8080,3000]}`))
	})

	cases := []struct {
		port    string
		allowed bool
	}{
		{"8080", true},
		{"3000", true},
		{"9090", false},
		{"22222", false},
		{"2280", false},
	}
	for _, c := range cases {
		allowed, err := p.isPortPubliclyAllowed(context.Background(), "sandbox-1", c.port)
		if err != nil {
			t.Fatalf("port %s: unexpected error: %v", c.port, err)
		}
		if allowed != c.allowed {
			t.Errorf("port %s: allowed = %v, want %v", c.port, allowed, c.allowed)
		}
	}
}

func TestIsPortPubliclyAllowed_UnrestrictedNull(t *testing.T) {
	p := newPortsTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"publicPorts":null}`))
	})

	allowed, err := p.isPortPubliclyAllowed(context.Background(), "sandbox-1", "9090")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Error("null allowlist must mean unrestricted")
	}
}

func TestIsPortPubliclyAllowed_UnpatchedAPI404(t *testing.T) {
	p := newPortsTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	allowed, err := p.isPortPubliclyAllowed(context.Background(), "sandbox-1", "9090")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Error("404 from an unpatched API must degrade to unrestricted")
	}
}

func TestGetSandboxPublicPorts_Cached(t *testing.T) {
	calls := 0
	p := newPortsTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"publicPorts":[8080]}`))
	})

	for i := 0; i < 3; i++ {
		if _, err := p.getSandboxPublicPorts(context.Background(), "sandbox-1"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if calls != 1 {
		t.Errorf("API called %d times, want 1 (cache miss only)", calls)
	}
}
