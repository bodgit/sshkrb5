// +build !windows,apcera

package sshkrb5

import (
	multierror "github.com/hashicorp/go-multierror"
	"github.com/openshift/gssapi"
)

type Client struct {
	lib *gssapi.Lib
	ctx *gssapi.CtxId
}

func NewClient() (c *Client, err error) {
	c = new(Client)
	c.lib, err = gssapi.Load(nil)
	return
}

func NewClientWithCredentials(_, _, _ string) (*Client, error) {
	return nil, errNotSupported
}

func NewClientWithKeytab(_, _, _ string) (*Client, error) {
	return nil, errNotSupported
}

func (c *Client) Close() error {
	return multierror.Append(c.DeleteSecContext(), c.lib.Unload())
}

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
		ctx, _, output, _, _, err := c.lib.InitSecContext(c.lib.GSS_C_NO_CREDENTIAL, c.ctx, service, c.lib.GSS_C_NO_OID, gssapiFlags, 0, c.lib.GSS_C_NO_CHANNEL_BINDINGS, input)
		defer output.Release()
		if err != nil && !c.lib.LastStatus.Major.ContinueNeeded() {
			return nil, false, err
		}
		c.ctx = ctx
		return output.Bytes(), c.lib.LastStatus.Major.ContinueNeeded(), nil
	}
}

func (c *Client) GetMIC(micFiled []byte) ([]byte, error) {
	message, err := c.lib.MakeBufferBytes(micFiled)
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

func (c *Client) DeleteSecContext() (err error) {
	err = c.ctx.DeleteSecContext()
	c.ctx = nil
	return
}
