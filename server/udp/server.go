// Copyright 2016 The Chihaya Authors. All rights reserved.
// Use of this source code is governed by the BSD 2-Clause license,
// which can be found in the LICENSE file.

// Package udp implements a BitTorrent tracker over the UDP protocol as per
// BEP 15.
package udp

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v2"

	"github.com/chihaya/chihaya"
	"github.com/chihaya/chihaya/pkg/bytepool"
	"github.com/chihaya/chihaya/server"
	"github.com/chihaya/chihaya/tracker"
)

func init() {
	server.Register("udp", constructor)
}

var promResponseDurationMilliseconds = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "chihaya_udp_response_duration_milliseconds",
		Help:    "The duration of time it takes to receieve and write a response to an API request",
		Buckets: prometheus.ExponentialBuckets(9.375, 2, 10),
	},
	[]string{"action", "error"},
)

type udpConfig struct {
	ListenAddr      string `yaml:"addr"`
	ReadBufferSize  int    `yaml:"read_size_buffer"`
	PrivateKey      string `yaml:"private_key"`
	AllowIPSpoofing bool   `yaml:"allow_ip_spoofing"`
}

// Server represents a UDP torrent tracker.
type Server struct {
	config  *udpConfig
	tracker *tracker.Tracker
	sock    *net.UDPConn

	closing chan struct{}
	booting chan struct{}
	wg      sync.WaitGroup
}

func (s *Server) serve() error {
	if s.sock != nil {
		return errors.New("server already booted")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", s.config.ListenAddr)
	if err != nil {
		close(s.booting)
		return err
	}

	sock, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		close(s.booting)
		return err
	}
	defer sock.Close()

	if s.config.ReadBufferSize > 0 {
		sock.SetReadBuffer(s.config.ReadBufferSize)
	}

	pool := bytepool.New(2048)
	s.sock = sock
	close(s.booting)

	for {
		// Check to see if we need to shutdown.
		select {
		case <-s.closing:
			return nil
		default:
		}

		// Read a UDP packet into a reusable buffer.
		buffer := pool.Get()
		sock.SetReadDeadline(time.Now().Add(time.Second))
		start := time.Now()
		n, addr, err := sock.ReadFromUDP(buffer)
		if err != nil {
			pool.Put(buffer)
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				// A temporary failure is not fatal; just pretend it never happened.
				continue
			}
			return err
		}

		// We got nothin'
		if n == 0 {
			pool.Put(buffer)
			continue
		}

		log.Println("Got UDP packet")

		s.wg.Add(1)
		go func(start time.Time) {
			defer s.wg.Done()
			defer pool.Put(buffer)

			// Handle the response.
			response, action, err := s.handlePacket(buffer[:n], addr)
			if len(response) > 0 {
				sock.WriteToUDP(response, addr)
			}
			log.Printf("Handled UDP packet: %s, %s, %s\n", response, action, err)

			// Record to Prometheus the time in milliseconds to receive, handle, and
			// respond to the request.
			duration := time.Since(start)
			if err != nil {
				promResponseDurationMilliseconds.WithLabelValues(action, err.Error()).Observe(float64(duration.Nanoseconds()) / float64(time.Millisecond))
			} else {
				promResponseDurationMilliseconds.WithLabelValues(action, "").Observe(float64(duration.Nanoseconds()) / float64(time.Millisecond))
			}
		}(start)
	}
}

// Start runs a UDP server, blocking until the server has shut down.
func (s *Server) Start() {
	log.Println("Starting UDP on ", s.config.ListenAddr)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-s.closing:
				return
			}
		}
	}()

	if err := s.serve(); err != nil {
		log.Printf("Failed to run UDP server: %s\n", err.Error())
	} else {
		log.Println("UDP server shut down cleanly")
	}
}

// Stop cleanly shuts down the server.
func (s *Server) Stop() {
	close(s.closing)
	s.sock.SetReadDeadline(time.Now())
	s.wg.Wait()
}

func constructor(srvcfg *chihaya.ServerConfig, tkr *tracker.Tracker) (server.Server, error) {
	cfg, err := newUDPConfig(srvcfg)
	if err != nil {
		return nil, errors.New("udp: invalid config: " + err.Error())
	}

	return &Server{
		config:  cfg,
		tracker: tkr,
		closing: make(chan struct{}),
		booting: make(chan struct{}),
	}, nil
}

func newUDPConfig(srvcfg *chihaya.ServerConfig) (*udpConfig, error) {
	bytes, err := yaml.Marshal(srvcfg.Config)
	if err != nil {
		return nil, err
	}

	var cfg udpConfig
	err = yaml.Unmarshal(bytes, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}
