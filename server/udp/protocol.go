// Copyright 2016 The Chihaya Authors. All rights reserved.
// Use of this source code is governed by the BSD 2-Clause license,
// which can be found in the LICENSE file.

package udp

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"

	"github.com/chihaya/chihaya"
	"github.com/chihaya/chihaya/pkg/event"
	"github.com/chihaya/chihaya/tracker"
)

const (
	connectActionID uint32 = iota
	announceActionID
	scrapeActionID
	errorActionID
	announceDualStackActionID
)

// Option-Types as described in BEP 41 and BEP 45.
const (
	optionEndOfOptions byte = 0x0
	optionNOP               = 0x1
	optionURLData           = 0x2
	optionIPv6              = 0x3
)

var (
	// initialConnectionID is the magic initial connection ID specified by BEP 15.
	initialConnectionID = []byte{0, 0, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80}

	// emptyIPs are the value of an IP field that has been left blank.
	emptyIPv4 = []byte{0, 0, 0, 0}
	emptyIPv6 = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	// eventIDs map values described in BEP 15 to Events.
	eventIDs = []event.Event{
		event.None,
		event.Completed,
		event.Started,
		event.Stopped,
	}

	errMalformedPacket = tracker.ClientError("malformed packet")
	errMalformedIP     = tracker.ClientError("malformed IP address")
	errMalformedEvent  = tracker.ClientError("malformed event ID")
	errUnknownAction   = tracker.ClientError("unknown action ID")
	errBadConnectionID = tracker.ClientError("bad connection ID")
)

// handlePacket decodes and processes one UDP request, returning the response.
func (s *Server) handlePacket(packet []byte, addr *net.UDPAddr) (response []byte, actionName string, err error) {
	if len(packet) < 16 {
		// Malformed, no client packets are less than 16 bytes.
		// We explicitly return nothing in case this is a DoS attempt.
		err = errMalformedPacket
		return
	}

	// Parse the headers of the UDP packet.
	connID := packet[0:8]
	actionID := binary.BigEndian.Uint32(packet[8:12])
	txID := packet[12:16]

	// Create a new Writer and defer setting the return value to its contents.
	writer := NewWriter(connID, txID)
	defer func() { response = writer.Response() }()

	// If this isn't requesting a new connection ID and the connection ID is
	// invalid, then fail.
	if actionID != connectActionID && !ValidConnectionID(connID, addr.IP, time.Now(), s.config.PrivateKey) {
		err = errBadConnectionID
		writer.WriteError(err)
		return
	}

	// Handle the requested action.
	switch actionID {
	case connectActionID:
		actionName = "connect"

		if !bytes.Equal(connID, initialConnectionID) {
			err = errMalformedPacket
			return
		}

		writer.WriteConnectionID(NewConnectionID(addr.IP, time.Now(), s.config.PrivateKey))
		return

	case announceActionID:
		actionName = "announce"

		var request *chihaya.AnnounceRequest
		request, err = parseAnnounce(s.config, packet, addr.IP)
		if err != nil {
			writer.WriteError(err)
			return
		}

		var resp *chihaya.AnnounceResponse
		resp, err = s.tracker.HandleAnnounce(request)
		if err != nil {
			writer.WriteError(err)
			return
		}

		writer.WriteAnnounce(resp)
		return

	case scrapeActionID:
		actionName = "scrape"

		var request *chihaya.ScrapeRequest
		request, err = parseScrape(s.config, packet)
		if err != nil {
			writer.WriteError(err)
			return
		}

		var resp *chihaya.ScrapeResponse
		resp, err = s.tracker.HandleScrape(request)
		if err != nil {
			writer.WriteError(err)
			return
		}

		writer.WriteScrape(resp)
		return

	default:
		err = errUnknownAction
		writer.WriteError(err)
		return
	}
}

// parseAnnounce parses an AnnounceRequest from a UDP packet.
func parseAnnounce(cfg *udpConfig, packet []byte, ip net.IP) (*chihaya.AnnounceRequest, error) {
	if len(packet) < 98 {
		return nil, errMalformedPacket
	}

	infohash := packet[16:36]
	peerID := packet[36:56]

	downloaded := binary.BigEndian.Uint64(packet[56:64])
	left := binary.BigEndian.Uint64(packet[64:72])
	uploaded := binary.BigEndian.Uint64(packet[72:80])

	eventID := packet[83]
	if eventID > 3 {
		return nil, errMalformedEvent
	}

	ipv4bytes := packet[84:88]
	if cfg.AllowIPSpoofing && !bytes.Equal(ipv4bytes, emptyIPv4) {
		ip = net.ParseIP(string(ipv4bytes))
	}

	if ip == nil {
		return nil, errMalformedIP
	} else if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}

	numWant := int32(binary.BigEndian.Uint32(packet[92:96]))
	if numWant <= 0 {
		numWant = 0
	}
	port := binary.BigEndian.Uint16(packet[96:98])

	ipv6, params, err := handleOptionalParameters(cfg, packet)
	if err != nil {
		return nil, err
	}

	return &chihaya.AnnounceRequest{
		Event:      eventIDs[eventID],
		InfoHash:   chihaya.InfoHashFromBytes(infohash),
		PeerID:     chihaya.PeerIDFromBytes(peerID),
		IPv4:       ip,
		IPv6:       ipv6,
		Port:       port,
		NumWant:    int32(numWant),
		Left:       left,
		Downloaded: downloaded,
		Uploaded:   uploaded,
		Params:     params,
	}, nil
}

// handleOptionalParameters parses the optional parameters as described in BEP
// 41 and updates an announce with the values parsed.
func handleOptionalParameters(cfg *udpConfig, packet []byte) (ipv6 net.IP, params chihaya.Params, err error) {
	if len(packet) <= 98 {
		return
	}

	optionStartIndex := 98
	for optionStartIndex < len(packet)-1 {
		option := packet[optionStartIndex]
		switch option {
		case optionEndOfOptions:
			return

		case optionNOP:
			optionStartIndex++

		case optionURLData:
			if optionStartIndex+1 > len(packet)-1 {
				return ipv6, params, errMalformedPacket
			}

			length := int(packet[optionStartIndex+1])
			if optionStartIndex+1+length > len(packet)-1 {
				return ipv6, params, errMalformedPacket
			}

			// TODO(jzelinskie): Actually parse the URL Data as described in BEP 41
			// into something that fulfills the chihaya.Params interface.

			optionStartIndex += 1 + length

		case optionIPv6:
			if optionStartIndex+19 > len(packet)-1 {
				return ipv6, params, errMalformedPacket
			}

			ipv6bytes := packet[optionStartIndex+1 : optionStartIndex+17]
			if cfg.AllowIPSpoofing && !bytes.Equal(ipv6bytes, emptyIPv6) {
				ipv6 = net.ParseIP(string(ipv6bytes)).To16()
				if ipv6 == nil {
					return ipv6, params, errMalformedIP
				}
			}

			optionStartIndex += 19

		default:
			return
		}
	}

	return
}

// parseScrape parses a ScrapeRequest from a UDP packet.
func parseScrape(_ *udpConfig, packet []byte) (*chihaya.ScrapeRequest, error) {
	// If a scrape isn't at least 36 bytes long, it's malformed.
	if len(packet) < 36 {
		return nil, errMalformedPacket
	}

	// Skip past the initial headers and check that the bytes left equal the
	// length of a valid list of infohashes.
	packet = packet[16:]
	if len(packet)%20 != 0 {
		return nil, errMalformedPacket
	}

	// Allocate a list of infohashes and append it to the list until we're out.
	var infohashes []chihaya.InfoHash
	for len(packet) >= 20 {
		infohashes = append(infohashes, chihaya.InfoHashFromBytes(packet[:20]))
		packet = packet[20:]
	}

	return &chihaya.ScrapeRequest{
		InfoHashes: infohashes,
	}, nil
}
