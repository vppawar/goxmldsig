package dsig

import (
	"time"

	"github.com/jonboulle/clockwork"
)

type Clock struct {
	wrapped clockwork.Clock
}

func (c *Clock) getWrapped() clockwork.Clock {
	if c == nil {
		return clockwork.NewRealClock()
	}

	return c.wrapped
}

func (c *Clock) After(d time.Duration) <-chan time.Time {
	return c.getWrapped().After(d)
}

func (c *Clock) Sleep(d time.Duration) {
	c.getWrapped().Sleep(d)
}

func (c *Clock) Now() time.Time {
	return c.getWrapped().Now()
}

func NewRealClock() *Clock {
	return &Clock{
		wrapped: clockwork.NewRealClock(),
	}
}

func NewFakeClock(wrapped clockwork.Clock) *Clock {
	return &Clock{
		wrapped: wrapped,
	}
}
