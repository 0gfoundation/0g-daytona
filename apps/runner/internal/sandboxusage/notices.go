// SPDX-License-Identifier: AGPL-3.0

package sandboxusage

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// The provider's billing tells a sandbox what is about to happen to it
// through the same file, as notices: its disk is past its size and when it
// is stopped for that, its owner's balance runs out, maintenance is planned.
//
// Billing sends the whole set on every poll (PUT /sandbox-notices). A sandbox
// missing from it has none. The set lapses after the validity billing gave
// it, so a billing that stops sending leaves no stale warnings behind. In the
// file, "notices" is then absent, which tells the sandbox nobody is telling
// it anything, unlike an empty list, which says there is nothing to tell.

// Notice is one warning to a sandbox.
type Notice struct {
	// Kind names the warning, as billing defines it: disk_near_full,
	// disk_over_size, balance_low, maintenance.
	Kind     string `json:"kind"`
	Severity string `json:"severity"` // info, warning or critical
	// Message says what happens and what the sandbox can do about it.
	Message string `json:"message"`
	// Deadline is when the provider acts, if it has a time.
	Deadline *time.Time `json:"deadline,omitempty"`
	// Action is what the provider does then, such as stop or archive.
	Action string `json:"action,omitempty"`
}

const (
	maxNoticeSandboxes   = 10000
	maxNoticesPerSandbox = 16
	maxNoticeMessage     = 2000
	maxNoticeWord        = 64
	// MaxNoticeValidity bounds how long one set stays in the files.
	MaxNoticeValidity = time.Hour
)

var (
	// ErrInvalidNotices wraps every rejection of a set.
	ErrInvalidNotices = errors.New("invalid notices")
	// ErrNoticesOff is returned while no environment files are written.
	ErrNoticesOff = errors.New("sandbox environment files are off on this runner")
)

// SetNotices replaces every sandbox's notices for validFor and rewrites the
// running sandboxes' files.
func (c *Collector) SetNotices(bySandbox map[string][]Notice, validFor time.Duration) error {
	if c.cfg.EnvDir == "" {
		return ErrNoticesOff
	}
	if validFor <= 0 || validFor > MaxNoticeValidity {
		return fmt.Errorf("%w: validity must be between 1 s and %s", ErrInvalidNotices, MaxNoticeValidity)
	}
	if len(bySandbox) > maxNoticeSandboxes {
		return fmt.Errorf("%w: more than %d sandboxes", ErrInvalidNotices, maxNoticeSandboxes)
	}
	set := make(map[string][]Notice, len(bySandbox))
	for id, ns := range bySandbox {
		if !validEnvName(id) {
			return fmt.Errorf("%w: sandbox ID %q", ErrInvalidNotices, id)
		}
		if len(ns) > maxNoticesPerSandbox {
			return fmt.Errorf("%w: sandbox %s has more than %d notices", ErrInvalidNotices, id, maxNoticesPerSandbox)
		}
		if len(ns) == 0 {
			continue
		}
		own := make([]Notice, len(ns))
		for i, n := range ns {
			if err := n.validate(); err != nil {
				return fmt.Errorf("%w: sandbox %s, notice %d: %v", ErrInvalidNotices, id, i, err)
			}
			if n.Deadline != nil {
				d := n.Deadline.UTC()
				n.Deadline = &d
			}
			own[i] = n
		}
		set[id] = own
	}
	c.mu.Lock()
	c.notices, c.noticesUntil = set, c.cfg.Now().Add(validFor)
	c.mu.Unlock()
	c.writeEnvFiles(false)
	return nil
}

// noticesFor is the sandbox's notices for its file: nil while no set is
// valid, else its list, empty when it has none. The slices are never
// modified once stored. c.mu must be held.
func (c *Collector) noticesFor(id string, at time.Time) *[]Notice {
	if !at.Before(c.noticesUntil) {
		return nil
	}
	ns := c.notices[id]
	if ns == nil {
		ns = []Notice{}
	}
	return &ns
}

func (n Notice) validate() error {
	if !isWord(n.Kind) {
		return fmt.Errorf("kind %q is not 1 to %d of a-z, 0-9 and _", n.Kind, maxNoticeWord)
	}
	switch n.Severity {
	case "info", "warning", "critical":
	default:
		return fmt.Errorf("severity %q is not info, warning or critical", n.Severity)
	}
	if n.Message == "" || len(n.Message) > maxNoticeMessage || !utf8.ValidString(n.Message) {
		return fmt.Errorf("message must be 1 to %d bytes of UTF-8", maxNoticeMessage)
	}
	if n.Action != "" && !isWord(n.Action) {
		return fmt.Errorf("action %q is not 1 to %d of a-z, 0-9 and _", n.Action, maxNoticeWord)
	}
	return nil
}

func isWord(s string) bool {
	if s == "" || len(s) > maxNoticeWord {
		return false
	}
	for _, ch := range s {
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '_' {
			return false
		}
	}
	return true
}
