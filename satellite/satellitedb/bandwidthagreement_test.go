// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"testing"
	"time"

	"github.com/skyrings/skyring-common/tools/uuid"
	"go.uber.org/zap"

	"storj.io/storj/pkg/storj"
)

func BenchmarkNonPrepared(b *testing.B) {
	uuidArray := make([]string, b.N)
	for index := 0; index < b.N; index++ {
		serialnum, err := uuid.New()
		if err != nil {
			panic(err)
		}
		uuidArray[index] = serialnum.String()
	}

	db, err := NewInMemory(zap.NewNop())
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			b.Fatal(err)
		}
	}()
	err = db.CreateTables()
	if err != nil {
		panic(err)
	}

	satDB := db.(*locked).db
	rawdb := satDB.(*DB).TestDBAccess()
	ctx := context.Background()

	b.ResetTimer()

	var saveOrderSQL = rawdb.Rebind(`INSERT INTO bwagreements ( serialnum, storage_node_id, uplink_id, action, total, created_at, expires_at ) VALUES ( ?, ?, ?, ?, ?, ?, ? )`)
	for index := 0; index < b.N; index++ {
		_, err = rawdb.ExecContext(ctx, saveOrderSQL,
			uuidArray[index],
			storj.NodeID{2},
			storj.NodeID{3},
			0,
			1,
			time.Now().UTC(),
			time.Now().UTC(),
		)
		if err != nil {
			panic(err)
		}
	}
}
func BenchmarkPrepared(b *testing.B) {
	uuidArray := make([]string, b.N)
	for index := 0; index < b.N; index++ {
		serialnum, err := uuid.New()
		if err != nil {
			panic(err)
		}
		uuidArray[index] = serialnum.String()
	}
	
	db, err := NewInMemory(zap.NewNop())
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			b.Fatal(err)
		}
	}()
	err = db.CreateTables()
	if err != nil {
		panic(err)
	}

	satDB := db.(*locked).db
	rawdb := satDB.(*DB).TestDBAccess()
	ctx := context.Background()

	b.ResetTimer()

	var saveOrderSQL = `INSERT INTO bwagreements ( serialnum, storage_node_id, uplink_id, action, total, created_at, expires_at ) VALUES ( ?, ?, ?, ?, ?, ?, ? )`
	statement, err := rawdb.PrepareContext(ctx, rawdb.Rebind(saveOrderSQL))
	if err != nil {
		panic(err)
	}

	for index := 0; index < b.N; index++ {
		_, err = statement.ExecContext(ctx,
			uuidArray[index],
			storj.NodeID{2},
			storj.NodeID{3},
			0,
			1,
			time.Now().UTC(),
			time.Now().UTC(),
		)
		if err != nil {
			panic(err)
		}
	}
}
