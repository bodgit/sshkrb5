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

// NewClientWithCredentials returns a new Client using the provided
// credentials.
//
// Deprecated: Use NewClient instead.
func NewClientWithCredentials(domain, username, password string) (*Client, error) {
	return NewClient(WithDomain(domain), WithUsername(username), WithPassword(password))
}

// NewClientWithKeytab returns a new Client using the provided keytab.
//
// Deprecated: Use NewClient instead.
func NewClientWithKeytab(domain, username, path string) (*Client, error) {
	return NewClient(WithDomain(domain), WithUsername(username), WithKeytab[Client](path))
}
