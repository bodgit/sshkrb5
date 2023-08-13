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
	return multierror.Append(c.DeleteSecContext(), c.lib.Unload()).ErrorOrNil()
}

// InitSecContext is called by the ssh.Client to initialis or advance the
// security context.
//
//nolint:funlen,nakedret
func (c *Client) InitSecContext(target string, token []byte, isGSSDelegCreds bool) (b []byte, cont bool, err error) {
	var (
		buffer, input *gssapi.Buffer
		service       *gssapi.Name
	)

	buffer, err = c.lib.MakeBufferString(target)
	if err != nil {
		return
	}

	defer func() {
		err = multierror.Append(err, buffer.Release()).ErrorOrNil()
	}()

	service, err = buffer.Name(c.lib.GSS_C_NT_HOSTBASED_SERVICE)
	if err != nil {
		return
	}

	defer func() {
		err = multierror.Append(err, service.Release()).ErrorOrNil()
	}()

	gssapiFlags := uint32(gssapi.GSS_C_MUTUAL_FLAG | gssapi.GSS_C_INTEG_FLAG)
	if isGSSDelegCreds {
		gssapiFlags |= gssapi.GSS_C_DELEG_FLAG
	}

	switch token {
	default:
		input, err = c.lib.MakeBufferBytes(token)
		if err != nil {
			return
		}

		defer func() {
			err = multierror.Append(err, input.Release()).ErrorOrNil()
		}()

		fallthrough
	case nil:
		var (
			ctx    *gssapi.CtxId
			output *gssapi.Buffer
		)

		//nolint:lll
		ctx, _, output, _, _, err = c.lib.InitSecContext(c.lib.GSS_C_NO_CREDENTIAL, c.ctx, service, c.lib.GSS_MECH_KRB5, gssapiFlags, 0, c.lib.GSS_C_NO_CHANNEL_BINDINGS, input)

		defer func() {
			err = multierror.Append(err, output.Release()).ErrorOrNil()
		}()

		if err != nil && !c.lib.LastStatus.Major.ContinueNeeded() {
			return
		}

		c.ctx, b, cont, err = ctx, output.Bytes(), c.lib.LastStatus.Major.ContinueNeeded(), nil

		return
	}
}

// GetMIC is called by the ssh.Client to authenticate the user using the
// negotiated security context.
func (c *Client) GetMIC(micField []byte) (b []byte, err error) {
	var message, token *gssapi.Buffer

	message, err = c.lib.MakeBufferBytes(micField)
	if err != nil {
		return
	}

	defer func() {
		err = multierror.Append(err, message.Release()).ErrorOrNil()
	}()

	token, err = c.ctx.GetMIC(gssapi.GSS_C_QOP_DEFAULT, message)
	if err != nil {
		return
	}

	defer func() {
		err = multierror.Append(err, token.Release()).ErrorOrNil()
	}()

	b = token.Bytes()

	return
}

// DeleteSecContext is called by the ssh.Client to tear down any active
// security context.
func (c *Client) DeleteSecContext() (err error) {
	err = c.ctx.DeleteSecContext()
	c.ctx = c.lib.GSS_C_NO_CONTEXT

	return
}
