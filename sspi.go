//go:build windows
// +build windows

package sshkrb5

import (
	"strings"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/kerberos"
	multierror "github.com/hashicorp/go-multierror"
)

// Client implements the ssh.GSSAPIClient interface.
type Client struct {
	creds *sspi.Credentials
	ctx   *kerberos.ClientContext
}

// NewClient returns a new Client using the current user.
func NewClient() (*Client, error) {

	c := new(Client)

	creds, err := kerberos.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}
	c.creds = creds

	return c, nil
}

// NewClientWithCredentials returns a new Client using the provided
// credentials.
func NewClientWithCredentials(domain, username, password string) (*Client, error) {

	c := new(Client)

	creds, err := kerberos.AcquireUserCredentials(domain, username, password)
	if err != nil {
		return nil, err
	}
	c.creds = creds

	return c, nil
}

// NewClientWithKeytab returns a new Client using the provided keytab.
func NewClientWithKeytab(_, _, _ string) (*Client, error) {
	return nil, errNotSupported
}

// Close deletes any active security context and unloads any underlying
// libraries as necessary.
func (c *Client) Close() error {
	return multierror.Append(c.DeleteSecContext(), c.creds.Release())
}

// InitSecContext is called by the ssh.Client to initialise or advance the
// security context.
func (c *Client) InitSecContext(target string, token []byte, isGSSDelegCreds bool) ([]byte, bool, error) {

	sspiFlags := uint32(sspi.ISC_REQ_MUTUAL_AUTH | sspi.ISC_REQ_CONNECTION | sspi.ISC_REQ_INTEGRITY)
	if isGSSDelegCreds {
		sspiFlags |= sspi.ISC_REQ_DELEGATE
	}

	switch token {
	case nil:
		ctx, completed, output, err := kerberos.NewClientContextWithFlags(c.creds, strings.ReplaceAll(target, "@", "/"), sspiFlags)
		if err != nil {
			return nil, false, err
		}
		c.ctx = ctx

		return output, !completed, nil
	default:
		completed, output, err := c.ctx.Update(token)
		if err != nil {
			return nil, false, err
		}

		return output, !completed, nil
	}
}

// GetMIC is called by the ssh.Client to authenticate the user using the
// negotiated security context.
func (c *Client) GetMIC(micField []byte) ([]byte, error) {

	token, err := c.ctx.MakeSignature(micField, 0, 0)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// DeleteSecContext is called by the ssh.Client to tear down any active
// security context.
func (c *Client) DeleteSecContext() error {
	return c.ctx.Release()
}
