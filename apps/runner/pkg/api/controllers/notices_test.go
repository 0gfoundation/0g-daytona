// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daytonaio/runner/internal/sandboxusage"
	"github.com/gin-gonic/gin"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
)

type fakeSetter struct {
	got      map[string][]sandboxusage.Notice
	validFor time.Duration
	err      error
}

func (f *fakeSetter) SetNotices(set map[string][]sandboxusage.Notice, validFor time.Duration) error {
	f.got, f.validFor = set, validFor
	return f.err
}

func putNotices(t *testing.T, setter NoticeSetter, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(common_errors.NewErrorMiddleware(func(ctx *gin.Context, err error) common_errors.ErrorResponse {
		return common_errors.ErrorResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
	}))
	r.PUT("/sandbox-notices", SetSandboxNotices(setter))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/sandbox-notices", strings.NewReader(body)))
	return w
}

func TestSetSandboxNotices(t *testing.T) {
	s := &fakeSetter{}
	w := putNotices(t, s, `{"valid_for_sec":180,"sandboxes":{"sb-1":[{"kind":"balance_low","severity":"warning","message":"Top up.","deadline":"2026-11-24T15:30:00Z","action":"stop"}]}}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d %s", w.Code, w.Body)
	}
	if n := s.got["sb-1"]; s.validFor != 3*time.Minute || len(n) != 1 || n[0].Kind != "balance_low" || n[0].Deadline == nil || n[0].Action != "stop" {
		t.Errorf("set = %+v for %s", s.got, s.validFor)
	}

	if w := putNotices(t, s, `{"sandboxes":`); w.Code != http.StatusBadRequest {
		t.Errorf("malformed body: status = %d", w.Code)
	}
	// 18446744074 s in nanoseconds wraps to about 0.29 s: it must reach the
	// setter as out of range, not as a short validity.
	for _, secs := range []string{"18446744074", "9223372036854775807", "3601"} {
		putNotices(t, s, `{"valid_for_sec":`+secs+`,"sandboxes":{}}`)
		if s.validFor <= sandboxusage.MaxNoticeValidity {
			t.Errorf("valid_for_sec %s reached the setter as %s", secs, s.validFor)
		}
	}
	s.err = fmt.Errorf("%w: kind", sandboxusage.ErrInvalidNotices)
	if w := putNotices(t, s, `{}`); w.Code != http.StatusBadRequest {
		t.Errorf("invalid set: status = %d", w.Code)
	}
	s.err = sandboxusage.ErrNoticesOff
	if w := putNotices(t, s, `{}`); w.Code != http.StatusNotImplemented {
		t.Errorf("files off: status = %d", w.Code)
	}
	if w := putNotices(t, nil, `{}`); w.Code != http.StatusNotImplemented {
		t.Errorf("no setter: status = %d", w.Code)
	}
}
