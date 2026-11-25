// SPDX-License-Identifier: AGPL-3.0

package docker

import "testing"

func TestPidsLimit(t *testing.T) {
	for _, off := range []int64{0, -1} {
		if p := pidsLimit(off); p != nil {
			t.Errorf("pidsLimit(%d) = %d, want unset", off, *p)
		}
	}
	if p := pidsLimit(4096); p == nil || *p != 4096 {
		t.Errorf("pidsLimit(4096) = %v, want 4096", p)
	}
}
