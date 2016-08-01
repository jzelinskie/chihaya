// Copyright 2016 The Chihaya Authors. All rights reserved.
// Use of this source code is governed by the BSD 2-Clause license,
// which can be found in the LICENSE file.

// Package tracker implements a protocol-independent, middleware-composed
// BitTorrent tracker.
package tracker

import (
	"errors"
	"fmt"
	"sync"

	"github.com/chihaya/chihaya"
)

// ClientError represents an error that should be exposed to the client over
// the BitTorrent protocol implementation.
type ClientError string

// Error implements the error interface for ClientError.
func (c ClientError) Error() string { return string(c) }

// Tracker represents a protocol-independent, middleware-composed BitTorrent
// tracker.
type Tracker struct {
	cfg            *chihaya.TrackerConfig
	handleAnnounce AnnounceHandler
	handleScrape   ScrapeHandler
	responsePool   sync.Pool
}

// NewTracker constructs a newly allocated Tracker composed of the middleware
// in the provided configuration.
func NewTracker(cfg *chihaya.TrackerConfig) (*Tracker, error) {
	var achain AnnounceChain
	for _, mwConfig := range cfg.AnnounceMiddleware {
		mw, ok := announceMiddlewareConstructors[mwConfig.Name]
		if !ok {
			return nil, errors.New("failed to find announce middleware: " + mwConfig.Name)
		}
		middleware, err := mw(mwConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to load announce middleware %q: %s", mwConfig.Name, err.Error())
		}
		achain.Append(middleware)
	}

	var schain ScrapeChain
	for _, mwConfig := range cfg.ScrapeMiddleware {
		mw, ok := scrapeMiddlewareConstructors[mwConfig.Name]
		if !ok {
			return nil, errors.New("failed to find scrape middleware: " + mwConfig.Name)
		}
		middleware, err := mw(mwConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to load scrape middleware %q: %s", mwConfig.Name, err.Error())
		}
		schain.Append(middleware)
	}

	return &Tracker{
		cfg:            cfg,
		handleAnnounce: achain.Handler(),
		handleScrape:   schain.Handler(),
		responsePool:   sync.Pool{New: func() interface{} { return &chihaya.AnnounceResponse{} }},
	}, nil
}

// HandleAnnounce runs an AnnounceRequest through the Tracker's middleware and
// returns the result.
//
// The response returned can be reused if it is given back to the tracker by
// calling ReturnAnnounceResponse. This is not strictly necessary but relieves
// pressure from the garbage collector.
func (t *Tracker) HandleAnnounce(req *chihaya.AnnounceRequest) (*chihaya.AnnounceResponse, error) {
	resp := t.responsePool.Get().(*chihaya.AnnounceResponse)
	err := t.handleAnnounce(t.cfg, req, resp)
	return resp, err
}

// ReturnAnnounceResponse returns the given AnnounceResponse to be reused by
// the tracker. It must not be used after returning it to the tracker.
func (t *Tracker) ReturnAnnounceResponse(resp *chihaya.AnnounceResponse) {
	if resp == nil {
		return
	}

	resp.Compact = false
	resp.Complete = 0
	resp.Incomplete = 0
	resp.Interval = 0
	resp.IPv4Peers = resp.IPv4Peers[:0]
	resp.IPv6Peers = resp.IPv6Peers[:0]
	resp.MinInterval = 0
	t.responsePool.Put(resp)
}

// HandleScrape runs a ScrapeRequest through the Tracker's middleware and
// returns the result.
func (t *Tracker) HandleScrape(req *chihaya.ScrapeRequest) (*chihaya.ScrapeResponse, error) {
	resp := &chihaya.ScrapeResponse{
		Files: make([]chihaya.Scrape, 0),
	}
	err := t.handleScrape(t.cfg, req, resp)
	return resp, err
}
