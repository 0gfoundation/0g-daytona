// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

// 0G patch: per-port public access. A public sandbox with a non-empty
// publicPorts allowlist only skips preview auth for ports in the list; all
// other ports fall back to the private-sandbox auth path.

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/daytonaio/common-go/pkg/utils"

	log "github.com/sirupsen/logrus"
)

// publicPortsInfo wraps the allowlist so an unrestricted sandbox (nil list)
// round-trips through the cache unambiguously.
type publicPortsInfo struct {
	Ports []int `json:"ports"`
}

// isPortPubliclyAllowed reports whether targetPort passes the sandbox's
// publicPorts allowlist. A nil/empty allowlist means unrestricted — every
// port follows the sandbox's public flag, which is upstream behavior.
func (p *Proxy) isPortPubliclyAllowed(ctx context.Context, sandboxId string, targetPort string) (bool, error) {
	info, err := p.getSandboxPublicPorts(ctx, sandboxId)
	if err != nil {
		return false, err
	}
	if len(info.Ports) == 0 {
		return true, nil
	}
	port, err := strconv.Atoi(targetPort)
	if err != nil {
		return false, nil
	}
	return slices.Contains(info.Ports, port), nil
}

// getSandboxPublicPorts fetches the allowlist from the API's
// GET /preview/:sandboxId/public-ports endpoint (0G patch on the API side),
// bypassing the generated client so the published api-client-go stays
// untouched. Any 4xx — including 404 from an unpatched API — is treated as
// unrestricted, so a fork proxy in front of a stock API degrades to upstream
// behavior instead of breaking previews.
func (p *Proxy) getSandboxPublicPorts(ctx context.Context, sandboxId string) (*publicPortsInfo, error) {
	cached, err := p.sandboxPublicPortsCache.Get(ctx, sandboxId)
	if err == nil {
		return cached, nil
	}

	var info publicPortsInfo
	err = utils.RetryWithExponentialBackoff(ctx, "getSandboxPublicPorts", proxyMaxRetries, proxyBaseDelay, proxyMaxDelay, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("%s/preview/%s/public-ports", p.config.DaytonaApiUrl, sandboxId), nil)
		if err != nil {
			return &utils.NonRetryableError{Err: err}
		}
		req.Header.Set("Authorization", "Bearer "+p.config.ProxyApiKey)

		res, err := p.userAPIHTTPClient.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()

		switch {
		case res.StatusCode == http.StatusOK:
			var body struct {
				PublicPorts []int `json:"publicPorts"`
			}
			if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body); err != nil {
				return &utils.NonRetryableError{Err: fmt.Errorf("decode public-ports response: %w", err)}
			}
			info.Ports = body.PublicPorts
			return nil
		case res.StatusCode >= 400 && res.StatusCode < 500 &&
			res.StatusCode != http.StatusRequestTimeout && res.StatusCode != http.StatusTooManyRequests:
			// Unpatched API (404) or stale sandbox — treat as unrestricted.
			info.Ports = nil
			return nil
		default:
			return fmt.Errorf("public-ports request failed: %s", res.Status)
		}
	})
	if err != nil {
		return nil, err
	}

	// publicPorts is immutable after create, so a long TTL is safe.
	if cacheErr := p.sandboxPublicPortsCache.Set(ctx, sandboxId, info, 1*time.Hour); cacheErr != nil {
		log.Errorf("Failed to set sandbox public ports in cache: %v", cacheErr)
	}

	return &info, nil
}
