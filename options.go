package sshkrb5

import "github.com/go-logr/logr"

// Option is the signature for all constructor options.
type Option[T Client | Server] func(*T) error

// WithLogger configures a logr.Logger in a Server.
func WithLogger[T Server](logger logr.Logger) Option[T] {
	return func(a *T) error {
		if x, ok := any(a).(*Server); ok {
			x.logger = logger.WithName("server")
		}

		return nil
	}
}
