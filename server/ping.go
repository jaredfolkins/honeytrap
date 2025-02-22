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
package server

import (
	"time"

	"github.com/jaredfolkins/honeytrap/event"
)

// ping delivers a ping event to the server indicate it's alive.
func (hc *Honeytrap) ping() error {
	hc.bus.Send(event.New(
		event.PingSensor,
		event.PingEvent,
	))

	return nil
}

// startPing initializes the ping runner.
func (hc *Honeytrap) startPing() {
	go func() {
		for {
			log.Debug("Yep, still alive")

			if err := hc.ping(); err != nil {
				log.Error("Error sending ping: %s", err.Error())
			}

			<-time.After(time.Second * 60)
		}
	}()
}
