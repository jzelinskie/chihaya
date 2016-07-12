// Copyright 2016 The Chihaya Authors. All rights reserved.
// Use of this source code is governed by the BSD 2-Clause license,
// which can be found in the LICENSE file.

package udp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"time"
)

const (
	// ttl is the number of seconds a connection ID should be valid according to
	// BEP 15.
	ttl = 2 * time.Minute

	// maxClockSkew is the maximum number of seconds of leeway to account for
	// unsynchronized clocks.
	maxClockSkew = 10 * time.Second
)

// NewConnectionID creates a new 8 byte connection identifier for UDP packets
// as described by BEP 15.
//
// The first 4 bytes of the connection identifier is a unix timestamp and the
// last 4 bytes are a truncated HMAC token created from the aforementioned
// unix timestamp and the source IP address of the UDP packet.
//
// Truncated HMAC is known to be safe for 2^(-n) where n is the size in bits
// of the truncated HMAC token. In this use case we have 32 bits, thus a
// forgery probability of approximately 1 in 4 billion.
func NewConnectionID(ip net.IP, now time.Time, key string) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf, uint32(now.UTC().Unix()))

	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(buf[:4])
	mac.Write(ip)
	macBytes := mac.Sum(nil)[:4]
	copy(buf[4:], macBytes)

	return buf
}

// ValidConnectionID determines whether a connection identifier is legitimate.
func ValidConnectionID(connectionID []byte, ip net.IP, now time.Time, key string) bool {
	ts := time.Unix(int64(binary.BigEndian.Uint32(connectionID[:4])), 0)
	if now.After(ts.Add(ttl)) || ts.After(now.Add(maxClockSkew)) {
		return false
	}

	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(connectionID[:4])
	mac.Write(ip)
	expectedMAC := mac.Sum(nil)[:4]
	return hmac.Equal(expectedMAC, connectionID[4:])
}
