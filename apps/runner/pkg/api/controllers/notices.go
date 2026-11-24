// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/daytonaio/runner/internal/sandboxusage"
	"github.com/gin-gonic/gin"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
)

// 0G: billing's warnings to its sandboxes (0g-sandbox#148), shown in each
// sandbox's own /run/0g/environment.json. Not part of Daytona's API.

// NoticeSetter takes billing's notices; *sandboxusage.Collector.
type NoticeSetter interface {
	SetNotices(bySandbox map[string][]sandboxusage.Notice, validFor time.Duration) error
}

// SetSandboxNoticesRequest replaces every sandbox's notices.
type SetSandboxNoticesRequest struct {
	// ValidForSec is how long the set stays in the files unless replaced.
	ValidForSec int64 `json:"valid_for_sec"`
	// Sandboxes maps a sandbox ID to its notices. A sandbox not listed has
	// none.
	Sandboxes map[string][]sandboxusage.Notice `json:"sandboxes"`
}

const maxNoticesBody = 4 << 20

// SetSandboxNotices handles PUT /sandbox-notices.
func SetSandboxNotices(setter NoticeSetter) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if setter == nil {
			ctx.Error(common_errors.NewCustomError(http.StatusNotImplemented, sandboxusage.ErrNoticesOff.Error(), "NOTICES_OFF"))
			return
		}
		var req SetSandboxNoticesRequest
		if err := json.NewDecoder(http.MaxBytesReader(ctx.Writer, ctx.Request.Body, maxNoticesBody)).Decode(&req); err != nil {
			ctx.Error(common_errors.NewInvalidBodyRequestError(err))
			return
		}
		err := setter.SetNotices(req.Sandboxes, time.Duration(req.ValidForSec)*time.Second)
		switch {
		case errors.Is(err, sandboxusage.ErrNoticesOff):
			ctx.Error(common_errors.NewCustomError(http.StatusNotImplemented, err.Error(), "NOTICES_OFF"))
		case err != nil:
			ctx.Error(common_errors.NewBadRequestError(err))
		default:
			ctx.Status(http.StatusNoContent)
		}
	}
}
