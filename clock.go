package dsig

import (
	"time"
)

// clock provides an interface that packages can use instead of directly
// using the time module, so that chronology-related behavior can be tested
type clock interface {
	Now() time.Time
}

type realClock struct{}

func (r *realClock) Now() time.Time {
	return time.Now()
}
