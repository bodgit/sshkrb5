package sshkrb5

import "github.com/go-logr/logr"

// Option is the signature for all constructor options.
type Option[T Client | Server] func(*T) error

// WithLogger configures a logr.Logger in a Server.
func WithLogger[T Client | Server](logger logr.Logger) Option[T] {
	return func(a *T) error {
		switch x := any(a).(type) {
		case *Client:
			x.logger = logger.WithName("client")
		case *Server:
			x.logger = logger.WithName("server")
		}

		return nil
	}
}

// WithRealm is an alias for WithDomain.
func WithRealm[T Client](realm string) Option[T] {
	return WithDomain[T](realm)
}

//nolint:nolintlint,unused
func unsupportedOption[T Client | Server](_ *T) error {
	return errNotSupported
}
