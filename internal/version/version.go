// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package version

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/zeebo/errs"
)

var (
	// Build represents the release information of this specific binary
	Build V
)

// TODO: should this be a protobuf?
type V struct {
	Timestamp  time.Time
	CommitHash string
	Version    Version
	Release    bool
}

// TODO: should this be a protobuf?
type Version struct {
	Major, Minor, Patch int
}

// ParseVersion turns semantic version val into a parsed Version struct
func ParseVersion(val string) (rv Version, err error) {
	fields := strings.Split(val, ".")
	if len(fields) != 3 || !strings.HasPrefix(fields[0], "v") {
		return rv, errs.New("invalid semantic version: %q", val)
	}
	rv.Major, err = strconv.Atoi(fields[0][1:])
	if err != nil {
		return rv, errs.New("invalid semantic version: %q", val)
	}
	rv.Minor, err = strconv.Atoi(fields[1])
	if err != nil {
		return rv, errs.New("invalid semantic version: %q", val)
	}
	rv.Patch, err = strconv.Atoi(fields[2])
	if err != nil {
		return rv, errs.New("invalid semantic version: %q", val)
	}
	return rv, nil
}

var (
	// these values are set through linker flags
	buildTimestamp  string
	buildCommitHash string
	buildVersion    string
	buildRelease    string
)

func init() {
	if buildTimestamp == "" &&
		buildCommitHash == "" &&
		buildVersion == "" &&
		buildRelease == "" {
		return
	}
	ts, err := strconv.ParseInt(buildTimestamp, 10, 64)
	if err != nil {
		panic(fmt.Sprintf("Invalid build timestamp: expected unix seconds from epoch: %v", err))
	}
	Build.Timestamp = time.Unix(ts, 0)
	Build.CommitHash = buildCommitHash
	Build.Version, err = ParseVersion(buildVersion)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse build version: %+v", err))
	}
	Build.Release = (strings.ToLower(buildRelease) == "true")
}
