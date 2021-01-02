// +build windows

package sshkrb5

import (
	"strings"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
	multierror "github.com/hashicorp/go-multierror"
)

type Client struct {
	creds *sspi.Credentials
	ctx   *negotiate.ClientContext
}

func NewClient() (*Client, error) {

	c := new(Client)

	creds, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}
	c.creds = creds

	return c, nil
}

func NewClientWithCredentials(domain, username, password string) (*Client, error) {

	c := new(Client)

	creds, err := negotiate.AcquireUserCredentials(domain, username, password)
	if err != nil {
		return nil, err
	}
	c.creds = creds

	return c, nil
}

func NewClientWithKeytab(_, _, _ string) (*Client, error) {
	return nil, errNotSupported
}

func (c *Client) Close() error {
	return multierror.Append(c.DeleteSecContext(), c.creds.Release())
}

func (c *Client) InitSecContext(target string, token []byte, isGSSDelegCreds bool) ([]byte, bool, error) {

	sspiFlags := uint32(sspi.ISC_REQ_MUTUAL_AUTH | sspi.ISC_REQ_CONNECTION | sspi.ISC_REQ_INTEGRITY)
	if isGSSDelegCreds {
		sspiFlags |= sspi.ISC_REQ_DELEGATE
	}

	switch token {
	case nil:
		ctx, output, err := negotiate.NewClientContextWithFlags(c.creds, strings.ReplaceAll(target, "@", "/"), sspiFlags)
		if err != nil {
			return nil, false, err
		}
		c.ctx = ctx

		return output, true, nil
	default:
		completed, output, err := c.ctx.Update(token)
		if err != nil {
			return nil, false, err
		}

		return output, !completed, nil
	}
}

func (c *Client) GetMIC(micFiled []byte) ([]byte, error) {

	token, err := c.ctx.MakeSignature(micFiled, 0, 0)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (c *Client) DeleteSecContext() error {
	return c.ctx.Release()
}