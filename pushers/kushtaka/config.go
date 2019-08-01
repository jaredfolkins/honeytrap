package kushtaka

import (
	"errors"

	"net/url"
)

var (
	// Unable to contact the Kushtaka server
	ErrServerUnreachable = errors.New("Unable to contact the kushtaka server. Is it up? Can the sensor query ping/traceroute to it?")
)

// Config defines a struct which holds configuration values for a SearchBackend.
type Config struct {

	// URL configures the Elasticsearch server and index to send messages to
	URL *url.URL `toml:"url"`

	// Insecure configures if the client should not verify tls configuration
	InsecureSkipVerify bool `toml:"insecure"`

	// Sniff defines if the client should find all nodes
	Sniff bool `toml:"sniff"`

	index string
}

// UnmarshalTOML deserializes the giving data into the config.
func (c *Config) UnmarshalTOML(p interface{}) error {
	return nil
}
