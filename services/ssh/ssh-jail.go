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
package ssh

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/fatih/color"
	"github.com/jaredfolkins/honeytrap/event"
	"github.com/jaredfolkins/honeytrap/pushers"
	"github.com/jaredfolkins/honeytrap/services"

	"bytes"

	"io/ioutil"

	"github.com/rs/xid"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	_ = services.Register("ssh-jail", Jail)
)

func Jail(options ...services.ServicerFunc) services.Servicer {
	s, err := getStorage()
	if err != nil {
		log.Errorf("Could not initialize storage: ", err.Error())
	}

	banner := "SSH-2.0-OpenSSH_6.6.1p1 2020Ubuntu-2ubuntu2"

	service := &sshJailService{
		key:    s.PrivateKey(),
		Banner: banner,
		MOTD:   motd,
		Credentials: []string{
			"*",
		},
	}

	for _, o := range options {
		o(service)
	}

	return service
}

type sshJailService struct {
	c pushers.Channel

	Banner string `toml:"banner"`
	MOTD   string `toml:"motd"`

	Credentials []string    `toml:"credentials"`
	key         *privateKey `toml:"private-key"`
}

func (s *sshJailService) CanHandle(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte("SSH"))
}

func (s *sshJailService) SetChannel(c pushers.Channel) {
	s.c = c
}

func (s *sshJailService) Handle(ctx context.Context, conn net.Conn) error {
	id := xid.New()

	config := ssh.ServerConfig{
		ServerVersion: s.Banner,
		PublicKeyCallback: func(cm ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.c.Send(event.New(
				services.EventOptions,
				event.Category("ssh"),
				event.Type("publickey-authentication"),
				event.SourceAddr(cm.RemoteAddr()),
				event.DestinationAddr(cm.LocalAddr()),
				event.Custom("ssh.sessionid", id.String()),
				event.Custom("ssh.username", cm.User()),
				event.Custom("ssh.publickey-type", key.Type()),
				event.Custom("ssh.publickey", hex.EncodeToString(key.Marshal())),
			))

			return nil, errors.New("Unknown key")
		},
		PasswordCallback: func(cm ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			s.c.Send(event.New(
				services.EventOptions,
				event.Category("ssh"),
				event.Type("password-authentication"),
				event.SourceAddr(cm.RemoteAddr()),
				event.DestinationAddr(cm.LocalAddr()),
				event.Custom("ssh.sessionid", id.String()),
				event.Custom("ssh.username", cm.User()),
				event.Custom("ssh.password", string(password)),
			))

			for _, credential := range s.Credentials {
				if credential == "*" {
					return nil, nil
				}

				parts := strings.Split(credential, ":")
				if len(parts) != 2 {
					continue
				}

				if cm.User() == parts[0] && string(password) == parts[1] {
					log.Debug("User authenticated successfully. user=%s password=%s", cm.User(), string(password))
					return nil, nil
				}
			}

			return nil, fmt.Errorf("Password rejected for %q", cm.User())
		},
	}

	config.AddHostKey(s.key)

	defer conn.Close()

	sconn, chans, reqs, err := ssh.NewServerConn(conn, &config)
	if err == io.EOF {
		// server closed connection
		return nil
	} else if err != nil {
		return err
	}

	defer func() {
		sconn.Close()
	}()

	go ssh.DiscardRequests(reqs)

	// https://tools.ietf.org/html/rfc4254
	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "session":
			// handleSession()
		case "forwarded-tcpip":
			decoder := PayloadDecoder(newChannel.ExtraData())

			s.c.Send(event.New(
				services.EventOptions,
				event.Category("ssh"),
				event.Type("ssh-channel"),
				event.SourceAddr(conn.RemoteAddr()),
				event.DestinationAddr(conn.LocalAddr()),
				event.Custom("ssh.sessionid", id.String()),
				event.Custom("ssh.channel-type", newChannel.ChannelType()),
				event.Custom("ssh.forwarded-tcpip.address-that-was-connected", decoder.String()),
				event.Custom("ssh.forwarded-tcpip.port-that-was-connected", fmt.Sprintf("%d", decoder.Uint32())),
				event.Custom("ssh.forwarded-tcpip.originator-host", decoder.String()),
				event.Custom("ssh.forwarded-tcpip.originator-port", fmt.Sprintf("%d", decoder.Uint32())),
				event.Payload(newChannel.ExtraData()),
			))

			channel, _, err := newChannel.Accept()
			if err == io.EOF {
				continue
			} else if err != nil {
				log.Errorf("Could not accept server channel: %s", err.Error())
				continue
			}

			data, err := ioutil.ReadAll(channel)
			if err != nil {
				log.Errorf("Could not read from direct-tcpip channel: %s", err.Error())
				continue
			}

			s.c.Send(event.New(
				services.EventOptions,
				event.Category("ssh"),
				event.Type("ssh-channel"),
				event.SourceAddr(conn.RemoteAddr()),
				event.DestinationAddr(conn.LocalAddr()),
				event.Custom("ssh.sessionid", id.String()),
				event.Custom("ssh.channel-type", newChannel.ChannelType()),
				event.Custom("ssh.forwarded-tcpip.address-that-was-connected", decoder.String()),
				event.Custom("ssh.forwarded-tcpip.port-that-was-connected", fmt.Sprintf("%d", decoder.Uint32())),
				event.Custom("ssh.forwarded-tcpip.originator-host", decoder.String()),
				event.Custom("ssh.forwarded-tcpip.originator-port", fmt.Sprintf("%d", decoder.Uint32())),
				event.Payload(data),
			))

			continue
		case "direct-tcpip":
			decoder := PayloadDecoder(newChannel.ExtraData())

			s.c.Send(event.New(
				services.EventOptions,
				event.Category("ssh"),
				event.Type("ssh-channel"),
				event.SourceAddr(conn.RemoteAddr()),
				event.DestinationAddr(conn.LocalAddr()),
				event.Custom("ssh.sessionid", id.String()),
				event.Custom("ssh.channel-type", newChannel.ChannelType()),
				event.Custom("ssh.direct-tcpip.host-to-connect", decoder.String()),
				event.Custom("ssh.direct-tcpip.port-to-connect", fmt.Sprintf("%d", decoder.Uint32())),
				event.Custom("ssh.direct-tcpip.originator-host", decoder.String()),
				event.Custom("ssh.direct-tcpip.originator-port", fmt.Sprintf("%d", decoder.Uint32())),
			))

			channel, _, err := newChannel.Accept()
			if err == io.EOF {
				continue
			} else if err != nil {
				log.Errorf("Could not accept server channel: %s", err.Error())
				continue
			}

			data, err := ioutil.ReadAll(channel)
			if err != nil {
				log.Errorf("Could not read from direct-tcpip channel: %s", err.Error())
				continue
			}

			s.c.Send(event.New(
				services.EventOptions,
				event.Category("ssh"),
				event.Type("ssh-channel"),
				event.SourceAddr(conn.RemoteAddr()),
				event.DestinationAddr(conn.LocalAddr()),
				event.Custom("ssh.sessionid", id.String()),
				event.Custom("ssh.channel-type", newChannel.ChannelType()),
				event.Custom("ssh.direct-tcpip.host-to-connect", decoder.String()),
				event.Custom("ssh.direct-tcpip.port-to-connect", fmt.Sprintf("%d", decoder.Uint32())),
				event.Custom("ssh.direct-tcpip.originator-host", decoder.String()),
				event.Custom("ssh.direct-tcpip.originator-port", fmt.Sprintf("%d", decoder.Uint32())),
				event.Payload(data),
			))

			continue
		default:
			s.c.Send(event.New(
				services.EventOptions,
				event.Category("ssh"),
				event.Type("ssh-channel"),
				event.SourceAddr(conn.RemoteAddr()),
				event.DestinationAddr(conn.LocalAddr()),
				event.Custom("ssh.sessionid", id.String()),
				event.Custom("ssh.channel-type", newChannel.ChannelType()),
				event.Payload(newChannel.ExtraData()),
			))

			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			log.Debugf("Unknown channel type: %s\n", newChannel.ChannelType())
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err == io.EOF {
			continue
		} else if err != nil {
			log.Errorf("Could not accept server channel: %s", err.Error())
			continue
		}

		func() {
			options := []event.Option{
				services.EventOptions,
				event.Category("ssh"),
				event.Type("ssh-request"),
				event.SourceAddr(conn.RemoteAddr()),
				event.DestinationAddr(conn.LocalAddr()),
				event.Custom("ssh.sessionid", id.String()),
			}

			defer s.c.Send(event.New(
				options...,
			))

			for req := range requests {
				log.Debugf("Request: %s %s %s %s\n", channel, req.Type, req.WantReply, req.Payload)

				options = append(options, event.Custom("ssh.request-type", req.Type))
				options = append(options, event.Custom("ssh.payload", req.Payload))

				b := false

				switch req.Type {
				case "shell":
					b = true
				case "pty-req":
					b = true
				case "env":
					b = true

					decoder := PayloadDecoder(req.Payload)

					payloads := []string{}

					for {
						if decoder.Available() == 0 {
							break
						}

						payload := decoder.String()
						payloads = append(payloads, payload)
					}

					options = append(options, event.Custom("ssh.env", payloads))
				case "tcpip-forward":
					decoder := PayloadDecoder(req.Payload)

					options = append(options, event.Custom("ssh.tcpip-forward.address-to-bind", decoder.String()))
					options = append(options, event.Custom("ssh.tcpip-forward.port-to-bind", fmt.Sprintf("%d", decoder.Uint32())))
				case "exec":
					b = true
				case "subsystem":
					b = true

					decoder := PayloadDecoder(req.Payload)
					options = append(options, event.Custom("ssh.subsystem", decoder.String()))
				default:
					log.Errorf("Unsupported request type=%s payload=%s", req.Type, string(req.Payload))
				}

				if !b {
					// no reply
				} else if err := req.Reply(b, nil); err != nil {
					log.Errorf("wantreply: ", err)
				}

				func() {
					if req.Type == "shell" {
						defer channel.Close()

						/*
							debootstrap trusty trusty/
						*/
						/*
							/var/run/motd.dynamic
							/etc/motd
							"Last login: Wed Jan  3 15:33:27 2018 from 172.16.84.1"
						*/
						cmd := exec.Command("firejail", fmt.Sprintf("--name=%s", id), fmt.Sprintf("--overlay-named=%s", id), "--quiet", "--private-dev", "--private-tmp", "--private-opt=aabb", "--", "bash")
						//cmd := exec.Command("firejail", fmt.Sprintf("--name=%s", id), fmt.Sprintf("--overlay-named=%s", id), "--quiet", "--private-dev", "--private-tmp", "--private-opt=busybox-armv6l", "--", "qemu-arm", "/opt/busybox-armv6l", "sh")
						cmd.Dir = "/root"
						cmd.Env = append(os.Environ())

						inPipe, err := cmd.StdinPipe()
						if err != nil {
							log.Error(color.RedString("%s", err.Error()))
							return
						}

						outPipe, err := cmd.StdoutPipe()
						if err != nil {
							log.Error(color.RedString("%s", err.Error()))
							return
						}
						errPipe, err := cmd.StderrPipe()
						if err != nil {
							log.Error(color.RedString("%s", err.Error()))
							return
						}

						if err := cmd.Start(); err != nil {
							log.Fatal(err)
							return
						}

						defer cmd.Process.Kill()

						// should only be started in req.Type == shell
						twrc := NewTypeWriterReadCloser(channel)
						var wrappedChannel io.ReadWriteCloser = twrc

						prompt := "root@host:~$ "

						term := terminal.NewTerminal(wrappedChannel, prompt)

						go func() {
							io.Copy(term, outPipe)
						}()

						go func() {
							io.Copy(term, errPipe)
						}()

						term.Write([]byte(s.MOTD))
						term.Write([]byte("Last login: Wed Jan  3 15:33:27 2018 from 172.16.84.1\n\n"))

						for {
							line, err := term.ReadLine()
							if err == io.EOF {
								return
							} else if err != nil {
								log.Errorf("Error reading from connection: %s", err.Error())
								return
							}

							if line == "exit" {
								channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
								return
							}

							if line == "" {
								continue
							}

							s.c.Send(event.New(
								services.EventOptions,
								event.Category("ssh"),
								event.Type("shell"),
								event.SourceAddr(conn.RemoteAddr()),
								event.DestinationAddr(conn.LocalAddr()),
								event.Custom("ssh.sessionid", id.String()),
								event.Custom("ssh.command", line),
							))

							inPipe.Write([]byte(fmt.Sprintf("%s\n", line)))
						}
					} else if req.Type == "exec" {
						defer channel.Close()

						decoder := PayloadDecoder(req.Payload)

						for {
							if decoder.Available() == 0 {
								break
							}

							payload := decoder.String()

							arguments := []string{fmt.Sprintf("--name=%s", id), fmt.Sprintf("--overlay-named=%s", id), "--quiet", "--private-dev", "--private-tmp", "--private-opt=aabb", "--", "bash", "-c"}
							arguments = append(arguments, payload)

							//							arguments := []string{fmt.Sprintf("--name=%s", id), fmt.Sprintf("--overlay-named=%s", id), "--quiet", "--private-dev", "--private-tmp", "--private-opt=busybox-armv6l", "--", "qemu-arm", "/opt/busybox-armv6l"}
							//arguments = append(arguments, strings.Split(payload, " ")...)

							cmd := exec.Command("firejail", arguments...)

							cmd.Env = append(os.Environ())
							cmd.Dir = "/root"

							inPipe, err := cmd.StdinPipe()
							if err != nil {
								log.Error(color.RedString("%s", err.Error()))
								return
							}

							outPipe, err := cmd.StdoutPipe()
							if err != nil {
								log.Error(color.RedString("%s", err.Error()))
								return
							}

							errPipe, err := cmd.StderrPipe()
							if err != nil {
								log.Error(color.RedString("%s", err.Error()))
								return
							}

							if err := cmd.Start(); err != nil {
								log.Fatal(err)
								return
							}

							defer cmd.Process.Kill()

							go func() {
								io.Copy(channel, outPipe)
							}()

							go func() {
								io.Copy(channel, errPipe)
							}()

							go func() {
								io.Copy(inPipe, channel)
							}()

							options2 := []event.Option{
								services.EventOptions,
								event.Category("ssh"),
								event.Type("exec"),
								event.SourceAddr(conn.RemoteAddr()),
								event.DestinationAddr(conn.LocalAddr()),
								event.Custom("ssh.sessionid", id.String()),
								event.Custom("ssh.command", payload),
							}

							if err := cmd.Wait(); err == nil {
								ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
								options2 = append(options2, event.Custom("ssh.command-exit-status", ws.ExitStatus()))
							} else if exitError, ok := err.(*exec.ExitError); !ok {
							} else {
								ws := exitError.Sys().(syscall.WaitStatus)
								options2 = append(options2, event.Custom("ssh.command-exit-status", ws.ExitStatus()))
							}

							s.c.Send(event.New(
								options2...,
							))

							channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						}

						return
					}
				}()
			}
		}()
	}

	return nil
}
