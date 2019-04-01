// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package rollup

import (
	"context"
	"time"

	"go.uber.org/zap"

	"storj.io/storj/pkg/accounting"
	"storj.io/storj/pkg/storj"
)

// Config contains configurable values for rollup
type Config struct {
	Interval time.Duration `help:"how frequently rollup should run" devDefault:"120s" default:"6h"`
}

// Service is the rollup service for totalling data on storage nodes on daily intervals
type Service struct {
	logger *zap.Logger
	ticker *time.Ticker
	db     accounting.DB
}

// New creates a new rollup service
func New(logger *zap.Logger, db accounting.DB, interval time.Duration) *Service {
	return &Service{
		logger: logger,
		ticker: time.NewTicker(interval),
		db:     db,
	}
}

// Run the Rollup loop
func (r *Service) Run(ctx context.Context) (err error) {
	r.logger.Info("Rollup service starting up")
	defer mon.Task()(&ctx)(&err)
	for {
		err = r.Rollup(ctx)
		if err != nil {
			r.logger.Error("Query failed", zap.Error(err))
		}
		select {
		case <-r.ticker.C: // wait for the next interval to happen
		case <-ctx.Done(): // or the Rollup is canceled via context
			return ctx.Err()
		}
	}
}

// Rollup aggregates storage and bandwidth amounts for the time interval
func (r *Service) Rollup(ctx context.Context) error {
	// only Rollup new things - get LastRollup
	lastRollup, err := r.db.LastTimestamp(ctx, accounting.LastRollup)
	if err != nil {
		return Error.Wrap(err)
	}
	rollupStats := make(accounting.RollupStats)
	latestTally, err := r.rollupStorage(ctx, lastRollup, rollupStats)
	if err != nil {
		return Error.Wrap(err)
	}
	err = r.rollupBW(ctx, lastRollup, rollupStats)
	if err != nil {
		return Error.Wrap(err)
	}
	err = r.db.SaveRollup(ctx, latestTally, rollupStats)
	if err != nil {
		return Error.Wrap(err)
	}
	return nil
}

// rollupStorage rolls up storage tally
func (r *Service) rollupStorage(ctx context.Context, lastRollup time.Time, rollupStats accounting.RollupStats) (time.Time, error) {
	var latestTally time.Time
	tallies, err := r.db.GetRawSince(ctx, lastRollup)
	if err != nil {
		return time.Now(), Error.Wrap(err)
	}
	if len(tallies) == 0 {
		r.logger.Info("Rollup found no new tallies")
		return time.Now(), nil
	}
	//loop through tallies and build Rollup
	for _, tallyRow := range tallies {
		node := tallyRow.NodeID
		if tallyRow.CreatedAt.After(latestTally) {
			latestTally = tallyRow.CreatedAt
		}
		//create or get AccoutingRollup day entry
		iDay := tallyRow.IntervalEndTime
		iDay = time.Date(iDay.Year(), iDay.Month(), iDay.Day(), 0, 0, 0, 0, iDay.Location())
		if rollupStats[iDay] == nil {
			rollupStats[iDay] = make(map[storj.NodeID]*accounting.Rollup)
		}
		if rollupStats[iDay][node] == nil {
			rollupStats[iDay][node] = &accounting.Rollup{NodeID: node, StartTime: iDay}
		}
		//increment data at rest sum
		switch tallyRow.DataType {
		case accounting.AtRest:
			rollupStats[iDay][node].AtRestTotal += tallyRow.DataTotal
		default:
			r.logger.Info("rollupStorage no longer supports non-accounting.AtRest datatypes")
		}
	}
	//remove the latest day (which we cannot know is complete), then push to DB
	latestTally = time.Date(latestTally.Year(), latestTally.Month(), latestTally.Day(), 0, 0, 0, 0, latestTally.Location())
	delete(rollupStats, latestTally)
	if len(rollupStats) == 0 {
		r.logger.Info("Rollup only found tallies for today")
		return time.Now(), nil
	}
	return latestTally, nil
}

// rollupBW aggregates the bandwidth rollups
func (r *Service) rollupBW(ctx context.Context, lastRollup time.Time, rollupStats accounting.RollupStats) error {
	//TODO
	return nil
}

// model storagenode_bandwidth_rollup (
// 	key    storagenode_id interval_start action
// 	index (
// 	    name storagenode_id_interval_start_interval_seconds
// 	    fields storagenode_id interval_start interval_seconds
// 	)

// 	field storagenode_id   blob
// 	field interval_start   utimestamp
// 	field interval_seconds uint
// 	field action           uint

// 	field allocated uint64
// 	field settled   uint64
// )

// switch tallyRow.DataType {
// // case accounting.BandwidthPut:
// // 	rollupStats[iDay][node].PutTotal += int64(tallyRow.DataTotal)
// // case accounting.BandwidthGet:
// // 	rollupStats[iDay][node].GetTotal += int64(tallyRow.DataTotal)
// // case accounting.BandwidthGetAudit:
// // 	rollupStats[iDay][node].GetAuditTotal += int64(tallyRow.DataTotal)
// // case accounting.BandwidthGetRepair:
// // 	rollupStats[iDay][node].GetRepairTotal += int64(tallyRow.DataTotal)
// // case accounting.BandwidthPutRepair:
// // 	rollupStats[iDay][node].PutRepairTotal += int64(tallyRow.DataTotal)
// case accounting.AtRest:
// 	rollupStats[iDay][node].AtRestTotal += tallyRow.DataTotal
// default:
// 	r.logger.Info("rollupStorage no longer supports non-accounting.AtRest datatypes")
// }
