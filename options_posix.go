//go:build !windows
// +build !windows

package sshkrb5

// WithStrictMode is the equivalent of GSSAPIStrictAcceptorCheck.
func WithStrictMode[T Server](strict bool) Option[T] {
	return func(a *T) error {
		if x, ok := any(a).(*Server); ok {
			x.strict = strict
		}

		return nil
	}
}
