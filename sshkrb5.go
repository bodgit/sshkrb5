/*
Package sshkrb5 implements the GSSAPIClient and GSSAPIServer interfaces in the
golang.org/x/crypto/ssh package.
*/
package sshkrb5

import (
	"errors"
	"os"
)

//nolint:nolintlint,unused
var (
	errNotSupported = errors.New("not supported")
	osHostname      = os.Hostname //nolint:gochecknoglobals
)
