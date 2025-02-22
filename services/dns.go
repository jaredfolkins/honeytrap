// Copyright 2016-2019 DutchSec (https://dutchsec.com/)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package services

import (
	"context"
	"fmt"
	"net"
	"reflect"

	"github.com/miekg/dns"

	"github.com/jaredfolkins/honeytrap/event"
	"github.com/jaredfolkins/honeytrap/listener"
	"github.com/jaredfolkins/honeytrap/pushers"
)

var (
	_ = Register("dns", DNS)
)

// Dns is a placeholder
func DNS(options ...ServicerFunc) Servicer {
	s := &dnsService{}
	for _, o := range options {
		o(s)
	}
	return s
}

type dnsService struct {
	c pushers.Channel
}

func (s *dnsService) SetChannel(c pushers.Channel) {
	s.c = c
}

func (s *dnsService) Handle(ctx context.Context, conn net.Conn) error {
	defer conn.Close()

	buff := make([]byte, 65535)

	if _, ok := conn.(*listener.DummyUDPConn); ok {
		n, err := conn.Read(buff[:])
		if err != nil {
			return err
		}

		buff = buff[:n]
	} else if _, ok := conn.(*net.TCPConn); ok {
		n, err := conn.Read(buff[:])
		if err != nil {
			return err
		}

		buff = buff[:n]
	} else {
		log.Error("Unsupported connection type: %s", reflect.TypeOf(conn))
		return nil
	}

	req := new(dns.Msg)
	if err := req.Unpack(buff[:]); err != nil {
		return err
	}

	s.c.Send(event.New(
		EventOptions,
		event.Category("dns"),
		event.Type("dns"),
		event.SourceAddr(conn.RemoteAddr()),
		event.DestinationAddr(conn.LocalAddr()),
		event.Custom("dns.id", fmt.Sprintf("%d", req.Id)),
		event.Custom("dns.opcode", fmt.Sprintf("%d", req.Opcode)),
		event.Custom("dns.message", fmt.Sprintf("Querying for: %#q", req.Question)),
		event.Custom("dns.questions", req.Question),
	))

	return nil
}
