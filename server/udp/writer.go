// Copyright 2016 The Chihaya Authors. All rights reserved.
// Use of this source code is governed by the BSD 2-Clause license,
// which can be found in the LICENSE file.

package udp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/chihaya/chihaya"
	"github.com/chihaya/chihaya/tracker"
)

// Writer abstracts writing responses for the UDP BitTorrent protocol.
type Writer struct {
	buffer        *bytes.Buffer
	connectionID  []byte
	transactionID []byte
}

// NewWriter returns a newly allocated UDP Writer.
func NewWriter(connectionID, transactionID []byte) *Writer {
	return &Writer{new(bytes.Buffer), connectionID, transactionID}
}

// WriteError writes the failure reason as a null-terminated string.
func (w *Writer) WriteError(err error) {
	// If the client wasn't at fault, acknowledge it.
	if _, ok := err.(tracker.ClientError); !ok {
		err = fmt.Errorf("internal error occurred: %s", err.Error())
	}

	w.writeHeader(errorActionID)
	w.buffer.WriteString(err.Error())
	w.buffer.WriteRune('\000')
}

// WriteAnnounce encodes an announce response by selecting the proper announce
// format based on the BitTorrent spec.
func (w *Writer) WriteAnnounce(resp *chihaya.AnnounceResponse) {
	if len(resp.IPv6Peers) > 0 {
		w.WriteAnnounceIPv6(resp)
	} else {
		w.WriteAnnounceIPv4(resp)
	}
}

// WriteAnnounceIPv6 encodes an announce response according to BEP 45.
func (w *Writer) WriteAnnounceIPv6(resp *chihaya.AnnounceResponse) {
	w.writeHeader(announceDualStackActionID)
	binary.Write(w.buffer, binary.BigEndian, uint32(resp.Interval/time.Second))
	binary.Write(w.buffer, binary.BigEndian, uint32(resp.Incomplete))
	binary.Write(w.buffer, binary.BigEndian, uint32(resp.Complete))
	binary.Write(w.buffer, binary.BigEndian, uint32(len(resp.IPv4Peers)))
	binary.Write(w.buffer, binary.BigEndian, uint32(len(resp.IPv6Peers)))

	for _, peer := range resp.IPv4Peers {
		w.buffer.Write(peer.IP)
		binary.Write(w.buffer, binary.BigEndian, peer.Port)
	}

	for _, peer := range resp.IPv6Peers {
		w.buffer.Write(peer.IP)
		binary.Write(w.buffer, binary.BigEndian, peer.Port)
	}
}

// WriteAnnounceIPv4 encodes an announce response according to BEP 15.
func (w *Writer) WriteAnnounceIPv4(resp *chihaya.AnnounceResponse) {
	w.writeHeader(announceActionID)
	binary.Write(w.buffer, binary.BigEndian, uint32(resp.Interval/time.Second))
	binary.Write(w.buffer, binary.BigEndian, uint32(resp.Incomplete))
	binary.Write(w.buffer, binary.BigEndian, uint32(resp.Complete))

	for _, peer := range resp.IPv4Peers {
		w.buffer.Write(peer.IP)
		binary.Write(w.buffer, binary.BigEndian, peer.Port)
	}
}

// WriteScrape encodes a scrape response according to BEP 15.
func (w *Writer) WriteScrape(resp *chihaya.ScrapeResponse) {
	w.writeHeader(scrapeActionID)

	for _, scrape := range resp.Files {
		binary.Write(w.buffer, binary.BigEndian, scrape.Complete)

		// We currently don't keep track of snatches.
		binary.Write(w.buffer, binary.BigEndian, uint32(0))

		binary.Write(w.buffer, binary.BigEndian, scrape.Incomplete)
	}
}

// WriteConnectionID encodes a new connection response according to BEP 15.
func (w *Writer) WriteConnectionID(connectionID []byte) {
	w.writeHeader(connectActionID)
	w.buffer.Write(connectionID)
}

// Response returns all the bytes written to a Writer.
func (w *Writer) Response() []byte {
	return w.buffer.Bytes()
}

// writeHeader writes the action and transaction ID to the response.
func (w *Writer) writeHeader(action uint32) {
	binary.Write(w.buffer, binary.BigEndian, action)
	w.buffer.Write(w.transactionID)
}
