//go:build !windows && apcera
// +build !windows,apcera

package sshkrb5

import (
	multierror "github.com/hashicorp/go-multierror"
	"github.com/openshift/gssapi"
)

// Client implements the ssh.GSSAPIClient interface.
type Client struct {
	lib *gssapi.Lib
	ctx *gssapi.CtxId
}

// NewClient returns a new Client using the current user.
func NewClient() (c *Client, err error) {
	c = new(Client)
	c.lib, err = gssapi.Load(nil)

	return
}

// NewClientWithCredentials returns a new Client using the provided
// credentials.
func NewClientWithCredentials(_, _, _ string) (*Client, error) {
	return nil, errNotSupported
}

// NewClientWithKeytab returns a new Client using the provided keytab.
func NewClientWithKeytab(_, _, _ string) (*Client, error) {
	return nil, errNotSupported
}

// Close deletes any active security context and unloads any underlying
// libraries as necessary.
func (c *Client) Close() error {
	return multierror.Append(c.DeleteSecContext(), c.lib.Unload())
}

// InitSecContext is called by the ssh.Client to initialis or advance the
// security context.
func (c *Client) InitSecContext(target string, token []byte, isGSSDelegCreds bool) ([]byte, bool, error) {
	buffer, err := c.lib.MakeBufferString(target)
	if err != nil {
		return nil, false, err
	}

	defer buffer.Release()

	service, err := buffer.Name(c.lib.GSS_C_NT_HOSTBASED_SERVICE)
	if err != nil {
		return nil, false, err
	}

	defer service.Release()

	gssapiFlags := uint32(gssapi.GSS_C_MUTUAL_FLAG | gssapi.GSS_C_INTEG_FLAG)
	if isGSSDelegCreds {
		gssapiFlags |= gssapi.GSS_C_DELEG_FLAG
	}

	var input *gssapi.Buffer

	switch token {
	default:
		input, err = c.lib.MakeBufferBytes(token)
		if err != nil {
			return nil, false, err
		}

		defer input.Release()

		fallthrough
	case nil:
		//nolint:lll
		ctx, _, output, _, _, err := c.lib.InitSecContext(c.lib.GSS_C_NO_CREDENTIAL, c.ctx, service, c.lib.GSS_MECH_KRB5, gssapiFlags, 0, c.lib.GSS_C_NO_CHANNEL_BINDINGS, input)
		defer output.Release()

		if err != nil && !c.lib.LastStatus.Major.ContinueNeeded() {
			return nil, false, err
		}

		c.ctx = ctx

		return output.Bytes(), c.lib.LastStatus.Major.ContinueNeeded(), nil
	}
}

// GetMIC is called by the ssh.Client to authenticate the user using the
// negotiated security context.
func (c *Client) GetMIC(micField []byte) ([]byte, error) {
	message, err := c.lib.MakeBufferBytes(micField)
	if err != nil {
		return nil, err
	}

	defer message.Release()

	token, err := c.ctx.GetMIC(gssapi.GSS_C_QOP_DEFAULT, message)
	if err != nil {
		return nil, err
	}

	defer token.Release()

	return token.Bytes(), nil
}

// DeleteSecContext is called by the ssh.Client to tear down any active
// security context.
func (c *Client) DeleteSecContext() (err error) {
	err = c.ctx.DeleteSecContext()
	c.ctx = c.lib.GSS_C_NO_CONTEXT

	return
}
