// SPDX-License-Identifier: AGPL-3.0

package docker

// UsesSnapshotEntrypoint reports whether sandboxes run their image entrypoint
// without the Daytona daemon (USE_SNAPSHOT_ENTRYPOINT).
func (d *DockerClient) UsesSnapshotEntrypoint() bool {
	return d.useSnapshotEntrypoint
}
