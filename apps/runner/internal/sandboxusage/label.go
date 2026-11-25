// SPDX-License-Identifier: AGPL-3.0

package sandboxusage

import (
	"fmt"
	"strconv"
)

// DataBytesLabel records, on a sandbox's backup image, the sandbox's own data
// in that image: everything it wrote before the backup, earlier restores
// included. A sandbox restored from a backup writes to a fresh writable layer
// on top of the image, so its writable layer alone no longer shows that data.
// The backup sets it at commit time (pkg/docker backup), and the collector
// adds it to the writable layer (daytona_sandbox_data_bytes).
const DataBytesLabel = "ai.0g.sandbox.data-bytes"

// ClearedDataLabel sets the label to 0 on an image that is not a backup, such
// as a snapshot made from a sandbox: sandboxes created from it share its data
// as their base and do not own it.
const ClearedDataLabel = "LABEL " + DataBytesLabel + "=0"

// maxCarriedBytes bounds the label. No sandbox carries a pebibyte; a larger
// value comes from an image this runner did not label, and would overflow
// the sums it goes into.
const maxCarriedBytes = 1 << 50

// CarriedBytes is the data a container carries over from its image: the
// label's value, 0 when absent or not an integer from 0 to maxCarriedBytes.
func CarriedBytes(labels map[string]string) int64 {
	v, err := strconv.ParseInt(labels[DataBytesLabel], 10, 64)
	if err != nil || v < 0 || v > maxCarriedBytes {
		return 0
	}
	return v
}

// BackupDataLabel is the LABEL instruction for a backup of a container with
// these labels and writable layer: the data it carried plus what it wrote.
func BackupDataLabel(labels map[string]string, sizeRw int64) string {
	if sizeRw < 0 {
		sizeRw = 0
	}
	return fmt.Sprintf("LABEL %s=%d", DataBytesLabel, CarriedBytes(labels)+sizeRw)
}
