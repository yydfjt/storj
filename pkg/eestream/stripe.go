// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package eestream

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/vivint/infectious"
	"go.uber.org/zap"
)

// StripeReader can read and decodes stripes from a set of readers
type StripeReader struct {
	scheme      ErasureScheme
	cond        *sync.Cond
	readerCount int
	bufs        map[int]*PieceBuffer
	inbufs      map[int][]byte
	inmap       map[int][]byte
	errmap      map[int]error
}

// NewStripeReader creates a new StripeReader from the given readers, erasure
// scheme and max buffer memory.
func NewStripeReader(rs map[int]io.ReadCloser, es ErasureScheme, mbm int) *StripeReader {
	readerCount := len(rs)

	r := &StripeReader{
		scheme:      es,
		cond:        sync.NewCond(&sync.Mutex{}),
		readerCount: readerCount,
		bufs:        make(map[int]*PieceBuffer, readerCount),
		inbufs:      make(map[int][]byte, readerCount),
		inmap:       make(map[int][]byte, readerCount),
		errmap:      make(map[int]error, readerCount),
	}

	bufSize := mbm / readerCount
	bufSize -= bufSize % es.ErasureShareSize()
	if bufSize < es.ErasureShareSize() {
		bufSize = es.ErasureShareSize()
	}

	for i := range rs {
		r.inbufs[i] = make([]byte, es.ErasureShareSize())
		r.bufs[i] = NewPieceBuffer(make([]byte, bufSize), es.ErasureShareSize(), r.cond)
		// Kick off a goroutine each reader to be copied into a PieceBuffer.
		go func(r io.Reader, buf *PieceBuffer) {
			_, err := io.Copy(buf, r)
			if err != nil {
				buf.SetError(err)
				return
			}
			buf.SetError(io.EOF)
		}(rs[i], r.bufs[i])
	}

	return r
}

// Close closes the StripeReader and all PieceBuffers.
func (r *StripeReader) Close() error {
	errs := make(chan error, len(r.bufs))
	for _, buf := range r.bufs {
		go func(c io.Closer) {
			errs <- c.Close()
		}(buf)
	}
	var first error
	for range r.bufs {
		err := <-errs
		if err != nil && first == nil {
			first = Error.Wrap(err)
		}
	}
	return first
}

// ReadStripe reads and decodes the num-th stripe and concatenates it to p. The
// return value is the updated byte slice.
func (r *StripeReader) ReadStripe(num int64, p []byte) ([]byte, error) {
	for i := range r.inmap {
		delete(r.inmap, i)
	}

	r.cond.L.Lock()
	defer r.cond.L.Unlock()

	for r.pendingReaders() {
		for r.readAvailableShares(num) == 0 {
			r.cond.Wait()
		}
		if r.hasEnoughShares() {
			out, err := r.scheme.Decode(p, r.inmap)
			if err != nil {
				if r.shouldWaitForMore(err) {
					continue
				}
				return nil, err
			}
			return out, nil
		}
	}
	s := fmt.Sprintf("stripedebug pending readers errmap len %d", len(r.errmap))
	zap.L().Debug(s)
	s = fmt.Sprintf("stripedebug pending readers errmap len %d", len(r.errmap))
	zap.L().Debug(s)
	s = fmt.Sprintf("stripedebug readercount %d", r.readerCount)
	zap.L().Debug(s)
	s = fmt.Sprintf("stripedebug required count %d", r.scheme.RequiredCount())
	zap.L().Debug(s)
	s = fmt.Sprintf("stripedebug inmmap len %d", len(r.inmap))
	zap.L().Debug(s)
	// could not read enough shares to attempt a decode
	return nil, r.combineErrs(num)
}

// readAvailableShares reads the available num-th erasure shares from the piece
// buffers without blocking. The return value n is the number of erasure shares
// read.
func (r *StripeReader) readAvailableShares(num int64) (n int) {
	for i, buf := range r.bufs {
		if r.inmap[i] != nil || r.errmap[i] != nil {
			continue
		}
		if buf.HasShare(num) {
			err := buf.ReadShare(num, r.inbufs[i])
			if err != nil {
				r.errmap[i] = err
			} else {
				r.inmap[i] = r.inbufs[i]
			}
			n++
		}
	}
	return n
}

// pendingReaders checks if there are any pending readers to get a share from.
func (r *StripeReader) pendingReaders() bool {
	goodReaders := r.readerCount - len(r.errmap)
	return goodReaders >= r.scheme.RequiredCount() && goodReaders > len(r.inmap)
}

// hasEnoughShares check if there are enough erasure shares read to attempt
// a decode.
func (r *StripeReader) hasEnoughShares() bool {
	return len(r.inmap) >= r.scheme.RequiredCount()+1 ||
		(len(r.inmap) == r.scheme.RequiredCount() && !r.pendingReaders())
}

// shouldWaitForMore checks the returned decode error if it makes sense to wait
// for more erasure shares to attempt an error correction.
func (r *StripeReader) shouldWaitForMore(err error) bool {
	// check if the error is due to error detection
	if !infectious.NotEnoughShares.Contains(err) &&
		!infectious.TooManyErrors.Contains(err) {
		return false
	}
	// check if there are more input buffers to wait for
	return r.pendingReaders()
}

// combineErrs makes a useful error message from the errors in errmap.
// combineErrs always returns an error.
func (r *StripeReader) combineErrs(num int64) error {
	if len(r.errmap) == 0 {
		return Error.New("programmer error: no errors to combine")
	}
	errstrings := make([]string, 0, len(r.errmap))
	for i, err := range r.errmap {
		errstrings = append(errstrings, fmt.Sprintf("\nerror retrieving piece %02d: %v", i, err))
	}
	sort.Strings(errstrings)
	return Error.New("failed to download stripe %d: %s", num, strings.Join(errstrings, ""))
}
