// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package version

import (
	"context"
	"flag"
)

var (
	serverEndpoint = flag.String("version.endpoint", "https://version.alpha.storj.io", "version server")
)

// Check confirms that the process is running an acceptable version. If not,
// an error is returned.
func Check(ctx context.Context, processName string) error {
	// TODO: check *serverEndpoint for processName and compare to Build struct.
	return nil
}
