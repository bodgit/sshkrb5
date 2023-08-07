package sshkrb5

// WithStrictMode is the equivalent of GSSAPIStrictAcceptorCheck.
func WithStrictMode[T Server](_ bool) Option[T] {
	return func(a *T) error {
		return errNotSupported
	}
}
