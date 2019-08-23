package kushtaka

import (
	"github.com/jaredfolkins/honeytrap/pushers"
)

var (
	_ = pushers.Register("kushtaka", New)
)

type Backend struct {
	Config

	ch chan map[string]interface{}
}

func New(options ...func(pushers.Channel) error) (pushers.Channel, error) {
	ch := make(chan map[string]interface{}, 100)

	c := Backend{
		ch: ch,
	}
	return c, nil
}
