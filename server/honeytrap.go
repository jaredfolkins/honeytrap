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
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-isatty"

	"github.com/fatih/color"

	"github.com/jaredfolkins/honeytrap/cmd"
	"github.com/jaredfolkins/honeytrap/config"

	"github.com/jaredfolkins/honeytrap/pushers"
	"github.com/jaredfolkins/honeytrap/pushers/eventbus"

	"github.com/jaredfolkins/honeytrap/services"
	_ "github.com/jaredfolkins/honeytrap/services/bannerfmt"
	_ "github.com/jaredfolkins/honeytrap/services/elasticsearch"
	_ "github.com/jaredfolkins/honeytrap/services/eos"
	_ "github.com/jaredfolkins/honeytrap/services/ethereum"
	_ "github.com/jaredfolkins/honeytrap/services/ftp"
	_ "github.com/jaredfolkins/honeytrap/services/ipp"
	_ "github.com/jaredfolkins/honeytrap/services/ldap"
	_ "github.com/jaredfolkins/honeytrap/services/redis"
	_ "github.com/jaredfolkins/honeytrap/services/smtp"
	_ "github.com/jaredfolkins/honeytrap/services/snmp"
	_ "github.com/jaredfolkins/honeytrap/services/ssh"
	_ "github.com/jaredfolkins/honeytrap/services/telnet"
	_ "github.com/jaredfolkins/honeytrap/services/vnc"

	"github.com/jaredfolkins/honeytrap/listener"
	_ "github.com/jaredfolkins/honeytrap/listener/agent"
	_ "github.com/jaredfolkins/honeytrap/listener/canary"
	_ "github.com/jaredfolkins/honeytrap/listener/netstack"
	_ "github.com/jaredfolkins/honeytrap/listener/netstack-experimental"
	_ "github.com/jaredfolkins/honeytrap/listener/socket"
	_ "github.com/jaredfolkins/honeytrap/listener/tap"
	_ "github.com/jaredfolkins/honeytrap/listener/tun"

	// proxies

	"github.com/jaredfolkins/honeytrap/event"
	"github.com/jaredfolkins/honeytrap/server/profiler"

	_ "github.com/jaredfolkins/honeytrap/pushers/console"
	_ "github.com/jaredfolkins/honeytrap/pushers/dshield"
	_ "github.com/jaredfolkins/honeytrap/pushers/elasticsearch"
	_ "github.com/jaredfolkins/honeytrap/pushers/file"
	_ "github.com/jaredfolkins/honeytrap/pushers/kafka"
	_ "github.com/jaredfolkins/honeytrap/pushers/marija"
	_ "github.com/jaredfolkins/honeytrap/pushers/pulsar"
	_ "github.com/jaredfolkins/honeytrap/pushers/rabbitmq"
	_ "github.com/jaredfolkins/honeytrap/pushers/raven"
	_ "github.com/jaredfolkins/honeytrap/pushers/slack"
	_ "github.com/jaredfolkins/honeytrap/pushers/splunk"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("honeytrap/server")

// Honeytrap defines a struct which coordinates the internal logic for the honeytrap
// container infrastructure.
type Honeytrap struct {
	config *config.Config

	profiler profiler.Profiler

	// TODO(nl5887): rename to bus, should we encapsulate this?
	bus *eventbus.EventBus

	token string

	dataDir string

	// Maps a port and a protocol to an array of pointers to services
	ports map[net.Addr][]*ServiceMap

	// added by jared
	channels      map[string]pushers.Channel
	isChannelUsed map[string]bool
	serviceList   map[string]*ServiceMap
	isServiceUsed map[string]bool // Used to check that every service is used by a port
}

// New returns a new instance of a Honeytrap struct.
// func New(conf *config.Config) *Honeytrap {
func New(options ...OptionFn) (*Honeytrap, error) {
	bus := eventbus.New()

	// Initialize all channels within the provided config.
	conf := &config.Default

	h := &Honeytrap{
		config:        conf,
		bus:           bus,
		profiler:      profiler.Dummy(),
		channels:      map[string]pushers.Channel{},
		isChannelUsed: make(map[string]bool),
		serviceList:   make(map[string]*ServiceMap),
		isServiceUsed: make(map[string]bool), // Used to check that every service is used by a port
	}

	for _, fn := range options {
		if err := fn(h); err != nil {
			return nil, err
		}
	}

	return h, nil
}

func (hc *Honeytrap) startAgentServer() {
	// as := proxies.NewAgentServer(hc.director, hc.pusher, hc.configig)
	// go as.ListenAndServe()
}

// EventServiceStarted will return a service started Event struct
func EventServiceStarted(service string) event.Event {
	return event.New(
		event.Category(service),
		event.ServiceSensor,
		event.ServiceStarted,
	)
}

// PrepareRun will prepare Honeytrap to run
func (hc *Honeytrap) PrepareRun() {
}

// Wraps a Servicer, adding some metadata
type ServiceMap struct {
	Service services.Servicer

	Name string
	Type string
}

var (
	ErrNoServicesGivenPort = fmt.Errorf("no services for the given ports")
)

/* Finds a service that can handle the given connection.
 * The service is picked (among those configured for the given port) as follows:
 *
 *     If there are no services for the given port, return an error
 *     If there is only one service, pick it
 *     For each service (as sorted in the config file):
 *         - If it does not implement CanHandle, pick it
 *         - If it implements CanHandle, peek the connection and pass the peeked
 *           data to CanHandle. If it returns true, pick it
 */
func (hc *Honeytrap) findService(conn net.Conn) (*ServiceMap, net.Conn, error) {
	localAddr := conn.LocalAddr()

	var serviceCandidates []*ServiceMap

	for k, sc := range hc.ports {
		if !compareAddr(k, localAddr) {
			continue
		}

		serviceCandidates = sc
	}

	if len(serviceCandidates) == 0 {
		return nil, nil, fmt.Errorf("No service configured for the given port")
	} else if len(serviceCandidates) == 1 {
		return serviceCandidates[0], conn, nil
	}

	peekUninitialized := true
	var tConn net.Conn
	var pConn *peekConnection
	var n int
	buffer := make([]byte, 1024)
	for _, service := range serviceCandidates {
		ch, ok := service.Service.(services.CanHandlerer)
		if !ok {
			// Service does not implement CanHandle, assume it can handle the connection
			return service, conn, nil
		}
		// Service implements CanHandle, initialize it if needed and run the checks
		if peekUninitialized {
			// wrap connection in a connection with deadlines
			tConn = TimeoutConn(conn, time.Second*30)
			pConn = PeekConnection(tConn)
			log.Debug("Peeking connection %s => %s", conn.RemoteAddr(), conn.LocalAddr())
			_n, err := pConn.Peek(buffer)
			n = _n // avoid silly "variable not used" warning
			if err != nil {
				return nil, nil, fmt.Errorf("could not peek bytes: %s", err.Error())
			}
			peekUninitialized = false
		}
		if ch.CanHandle(buffer[:n]) {
			// Service supports payload
			return service, pConn, nil
		}
	}
	// There are some services for that port, but non can handle the connection.
	// Let the caller deal with it.
	return nil, nil, fmt.Errorf("No suitable service for the given port")
}

func (hc *Honeytrap) heartbeat() {
	beat := time.Tick(30 * time.Second)

	count := 0

	for range beat {
		hc.bus.Send(event.New(
			event.Sensor("honeytrap"),
			event.Category("heartbeat"),
			event.SeverityInfo,
			event.Custom("sequence", count),
		))

		count++
	}
}

// Addr, proto, port, error
func ToAddr(input string) (net.Addr, string, int, error) {
	parts := strings.Split(input, "/")

	if len(parts) != 2 {
		return nil, "", 0, fmt.Errorf("wrong format (needs to be \"protocol/(host:)port\")")
	}

	proto := parts[0]

	host, port, err := net.SplitHostPort(parts[1])
	if err != nil {
		port = parts[1]
	}

	portUint16, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, "", 0, fmt.Errorf("error parsing port value: %s", err.Error())
	}

	switch proto {
	case "tcp":
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
		return addr, proto, int(portUint16), err
	case "udp":
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
		return addr, proto, int(portUint16), err
	default:
		return nil, "", 0, fmt.Errorf("unknown protocol %s", proto)
	}
}

func IsTerminal(f *os.File) bool {
	if isatty.IsTerminal(f.Fd()) {
		return true
	} else if isatty.IsCygwinTerminal(f.Fd()) {
		return true
	}

	return false
}

func compareAddr(addr1 net.Addr, addr2 net.Addr) bool {
	if ta1, ok := addr1.(*net.TCPAddr); ok {
		ta2, ok := addr2.(*net.TCPAddr)
		if !ok {
			return false
		}

		if ta1.Port != ta2.Port {
			return false
		}

		if ta1.IP == nil {
		} else if ta2.IP == nil {
		} else if !ta1.IP.Equal(ta2.IP) {
			return false
		}

		return true
	} else if ua1, ok := addr1.(*net.UDPAddr); ok {
		ua2, ok := addr2.(*net.UDPAddr)
		if !ok {
			return false
		}

		if ua1.Port != ua2.Port {
			return false
		}

		if ua1.IP == nil {
		} else if ua2.IP == nil {
		} else if !ua1.IP.Equal(ua2.IP) {
			return false
		}

		return true
	}

	return false
}

func (hc *Honeytrap) ConfigureChannels() {

	for key, s := range hc.config.Channels {
		x := struct {
			Type string `toml:"type"`
		}{}

		err := hc.config.PrimitiveDecode(s, &x)
		if err != nil {
			log.Error("Error parsing configuration of channel: %s", err.Error())
			continue
		}

		if x.Type == "" {
			log.Error("Error parsing configuration of channel %s: type not set", key)
			continue
		}

		if channelFunc, ok := pushers.Get(x.Type); !ok {
			log.Error("Channel %s not supported on platform (%s)", x.Type, key)
		} else if d, err := channelFunc(
			pushers.WithConfig(s, hc.config),
		); err != nil {
			log.Fatalf("Error initializing channel %s(%s): %s", key, x.Type, err)
		} else {
			hc.channels[key] = d
			hc.isChannelUsed[key] = false
		}
	}

}

// subscribe default to global bus
// maybe we can rewrite pushers / channels to use global bus instead
func (hc *Honeytrap) ConfigureBus() {
	bc := pushers.NewBusChannel()
	hc.bus.Subscribe(bc)

	for _, s := range hc.config.Filters {
		x := struct {
			Channels   []string `toml:"channel"`
			Services   []string `toml:"services"`
			Categories []string `toml:"categories"`
		}{}

		err := hc.config.PrimitiveDecode(s, &x)
		if err != nil {
			log.Error("Error parsing configuration of filter: %s", err.Error())
			continue
		}

		for _, name := range x.Channels {
			channel, ok := hc.channels[name]
			if !ok {
				log.Error("Could not find channel %s for filter", name)
				continue
			}

			hc.isChannelUsed[name] = true
			channel = pushers.TokenChannel(channel, hc.token)

			if len(x.Categories) != 0 {
				channel = pushers.FilterChannel(channel, pushers.RegexFilterFunc("category", x.Categories))
			}

			if len(x.Services) != 0 {
				channel = pushers.FilterChannel(channel, pushers.RegexFilterFunc("service", x.Services))
			}

			if err := hc.bus.Subscribe(channel); err != nil {
				log.Error("Could not add channel %s to bus: %s", name, err.Error())
			}
		}
	}

	for name, isUsed := range hc.isChannelUsed {
		if !isUsed {
			log.Warningf("Channel %s is unused. Did you forget to add a filter?", name)
		}
	}

}

func (hc *Honeytrap) ConfigureServices() struct {
	Type string `toml:"type"`
} {
	// initialize listener
	x := struct {
		Type string `toml:"type"`
	}{}

	if err := hc.config.PrimitiveDecode(hc.config.Listener, &x); err != nil {
		log.Error("Error parsing configuration of listener: %s", err.Error())
	}

	if x.Type == "" {
		fmt.Println(color.RedString("Listener not set"))
	}

	// same for proxies
	for key, s := range hc.config.Services {
		x := struct {
			Type     string `toml:"type"`
			Director string `toml:"director"`
			Port     string `toml:"port"`
		}{}

		if err := hc.config.PrimitiveDecode(s, &x); err != nil {
			log.Error("Error parsing configuration of service %s: %s", key, err.Error())
			continue
		}

		if x.Port != "" {
			log.Error("Ports in services are deprecated, add services to ports instead")
			continue
		}

		// individual configuration per service
		options := []services.ServicerFunc{
			services.WithChannel(hc.bus),
			services.WithConfig(s, hc.config),
		}

		fn, ok := services.Get(x.Type)
		if !ok {
			log.Error(color.RedString("Could not find type %s for service %s", x.Type, key))
			continue
		}

		service := fn(options...)
		hc.serviceList[key] = &ServiceMap{
			Service: service,
			Name:    key,
			Type:    x.Type,
		}
		hc.isServiceUsed[key] = false
		log.Infof("Configured service %s (%s)", x.Type, key)
	}

	return x
}

func (hc *Honeytrap) ConfigureListener(ctx context.Context, x struct {
	Type string `toml:"type"`
}) listener.Listener {
	listenerFunc, ok := listener.Get(x.Type)
	if !ok {
		fmt.Println(color.RedString("Listener %s not support on platform", x.Type))
		return nil
	}

	l, err := listenerFunc(
		listener.WithChannel(hc.bus),
		listener.WithConfig(hc.config.Listener, hc.config),
	)
	if err != nil {
		log.Fatalf("Error initializing listener %s: %s", x.Type, err)
	}

	hc.ports = make(map[net.Addr][]*ServiceMap)
	for _, s := range hc.config.Ports {
		x := struct {
			Port     string   `toml:"port"`
			Ports    []string `toml:"ports"`
			Services []string `toml:"services"`
		}{}

		if err := hc.config.PrimitiveDecode(s, &x); err != nil {
			log.Error("Error parsing configuration of generic ports: %s", err.Error())
			continue
		}

		var ports []string
		if x.Ports != nil {
			ports = x.Ports
		}
		if x.Port != "" {
			ports = append(ports, x.Port)
		}
		if x.Port != "" && x.Ports != nil {
			log.Warning("Both \"port\" and \"ports\" were defined, this can be confusing")
		} else if x.Port == "" && x.Ports == nil {
			log.Error("Neither \"port\" nor \"ports\" were defined")
			continue
		}

		if len(x.Services) == 0 {
			log.Warning("No services defined for port(s) " + strings.Join(ports, ", "))
		}

		for _, portStr := range ports {
			addr, _, _, err := ToAddr(portStr)
			if err != nil {
				log.Error("Error parsing port string: %s", err.Error())
				continue
			}
			if addr == nil {
				log.Error("Failed to bind: addr is nil")
				continue
			}

			// Get the services from their names
			var servicePtrs []*ServiceMap
			for _, serviceName := range x.Services {
				ptr, ok := hc.serviceList[serviceName]
				if !ok {
					log.Error("Unknown service '%s' for port %s", serviceName, portStr)
					continue
				}
				servicePtrs = append(servicePtrs, ptr)
				hc.isServiceUsed[serviceName] = true
			}
			if len(servicePtrs) == 0 {
				log.Errorf("Port %s has no valid services, it won't be listened on", portStr)
				continue
			}

			found := false
			for k, _ := range hc.ports {
				if !compareAddr(k, addr) {
					continue
				}

				found = true
			}

			if found {
				log.Error("Port %s was already defined, ignoring the newer definition", portStr)
				continue
			}

			hc.ports[addr] = servicePtrs

			a, ok := l.(listener.AddAddresser)
			if !ok {
				log.Error("Listener error")
				continue
			}
			a.AddAddress(addr)

			log.Infof("Configured port %s/%s", addr.Network(), addr.String())
		}
	}

	for name, isUsed := range hc.isServiceUsed {
		if !isUsed {
			log.Warningf("Service %s is defined but not used", name)
		}
	}

	if len(hc.config.Undecoded()) != 0 {
		log.Warningf("Unrecognized keys in configuration: %v", hc.config.Undecoded())
	}

	if err := l.Start(ctx); err != nil {
		fmt.Println(color.RedString("Error starting listener: %s", err.Error()))
	}

	return l
}

// Run will start honeytrap
func (hc *Honeytrap) Run(ctx context.Context) {
	fmt.Println(color.HiBlueString("Kushtaka-sensor startin (%s)...", hc.token))
	fmt.Println(color.HiBlueString("Version: %s (%s)", cmd.Version, cmd.ShortCommitID))
	log.Debugf("Using datadir: %s", hc.dataDir)

	go hc.heartbeat()

	// sane defaults!
	hc.profiler.Start()
	hc.ConfigureChannels()
	hc.ConfigureBus()
	x := hc.ConfigureServices()
	l := hc.ConfigureListener(ctx, x)

	incoming := make(chan net.Conn)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				panic(err)
			}

			incoming <- conn

			// in case of goroutine starvation
			// with many connection and single procs
			runtime.Gosched()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case conn := <-incoming:
			go hc.handle(conn)
		}
	}
}

func (hc *Honeytrap) handle(conn net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			trace := make([]byte, 1024)
			count := runtime.Stack(trace, true)
			log.Errorf("Error: %s", err)
			log.Errorf("Stack of %d bytes: %s\n", count, string(trace))
			return
		}
	}()

	defer conn.Close()

	defer func() {
		if r := recover(); r != nil {
			message := event.Message("%+v", r)
			if err, ok := r.(error); ok {
				message = event.Message("%+v", err)
			}

			hc.bus.Send(event.New(
				event.SeverityFatal,
				event.SourceAddr(conn.RemoteAddr()),
				event.DestinationAddr(conn.LocalAddr()),
				event.Stack(),
				message,
			))
		}
	}()

	log.Debug("Accepted connection for %s => %s", conn.RemoteAddr(), conn.LocalAddr())
	defer log.Debug("Disconnected connection for %s => %s", conn.RemoteAddr(), conn.LocalAddr())

	/* conn is the original connection. newConn can be either the same
	 * connection, or a wrapper in the form of a PeekConnection.
	 */
	sm, newConn, err := hc.findService(conn)
	if sm == nil {
		log.Debug("No suitable handler for %s => %s: %s", conn.RemoteAddr(), conn.LocalAddr(), err.Error())
		return
	}

	log.Debug("Handling connection for %s => %s %s(%s)", conn.RemoteAddr(), conn.LocalAddr(), sm.Name, sm.Type)

	newConn = TimeoutConn(newConn, time.Second*30)

	ctx := context.Background()
	if err := sm.Service.Handle(ctx, newConn); err != nil {
		log.Errorf(color.RedString("Error handling service: %s: %s", sm.Name, err.Error()))
	}
}

// Stop will stop Honeytrap
func (hc *Honeytrap) Stop() {
	hc.profiler.Stop()

	fmt.Println(color.YellowString("Honeytrap stopped."))
}
