//go:build !windows && apcera
// +build !windows,apcera

package sshkrb5

import (
	"github.com/go-logr/logr"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/openshift/gssapi"
)

// WithConfig sets the configuration in the Client.
func WithConfig[T Client](_ string) Option[T] {
	return unsupportedOption[T]
}

// WithDomain sets the Kerberos domain in the Client.
func WithDomain[T Client](_ string) Option[T] {
	return unsupportedOption[T]
}

// WithUsername sets the username in the Client.
func WithUsername[T Client](_ string) Option[T] {
	return unsupportedOption[T]
}

// WithPassword sets the password in the Client.
func WithPassword[T Client](_ string) Option[T] {
	return unsupportedOption[T]
}

// WithKeytab sets the keytab path in either a Client or Server.
func WithKeytab[T Client | Server](_ string) Option[T] {
	return unsupportedOption[T]
}

// Client implements the ssh.GSSAPIClient interface.
type Client struct {
	lib *gssapi.Lib
	ctx *gssapi.CtxId

	logger logr.Logger
}

// NewClient returns a new Client using the current user.
func NewClient(options ...Option[Client]) (c *Client, err error) {
	c = &Client{
		logger: logr.Discard(),
	}

	for _, option := range options {
		if err = option(c); err != nil {
			return nil, err
		}
	}

	c.lib, err = gssapi.Load(nil)

	return
}

// Close deletes any active security context and unloads any underlying
// libraries as necessary.
func (c *Client) Close() error {
	return multierror.Append(c.DeleteSecContext(), c.lib.Unload()).ErrorOrNil()
}

// InitSecContext is called by the ssh.Client to initialise or advance the
// security context.
func (c *Client) InitSecContext(target string, token []byte, isGSSDelegCreds bool) (b []byte, cont bool, err error) {
	buffer, err := c.lib.MakeBufferString(target)
	if err != nil {
		return nil, false, err
	}

	defer func() {
		err = multierror.Append(err, buffer.Release()).ErrorOrNil()
	}()

	service, err := buffer.Name(c.lib.GSS_C_NT_HOSTBASED_SERVICE)
	if err != nil {
		return nil, false, err
	}

	defer func() {
		err = multierror.Append(err, service.Release()).ErrorOrNil()
	}()

	gssapiFlags := uint32(gssapi.GSS_C_MUTUAL_FLAG | gssapi.GSS_C_INTEG_FLAG)
	if isGSSDelegCreds {
		gssapiFlags |= gssapi.GSS_C_DELEG_FLAG
	}

	var input *gssapi.Buffer

	switch len(token) {
	default:
		input, err = c.lib.MakeBufferBytes(token)
		if err != nil {
			return nil, false, err
		}

		defer func() {
			err = multierror.Append(err, input.Release()).ErrorOrNil()
		}()

		fallthrough
	case 0:
		//nolint:lll
		ctx, _, output, _, _, err := c.lib.InitSecContext(c.lib.GSS_C_NO_CREDENTIAL, c.ctx, service, c.lib.GSS_MECH_KRB5, gssapiFlags, 0, c.lib.GSS_C_NO_CHANNEL_BINDINGS, input)
		if err != nil && !c.lib.LastStatus.Major.ContinueNeeded() {
			return nil, false, err
		}

		defer func() {
			err = multierror.Append(err, output.Release()).ErrorOrNil()
		}()

		c.ctx = ctx

		return output.Bytes(), c.lib.LastStatus.Major.ContinueNeeded(), nil
	}
}

// GetMIC is called by the ssh.Client to authenticate the user using the
// negotiated security context.
func (c *Client) GetMIC(micField []byte) (b []byte, err error) {
	message, err := c.lib.MakeBufferBytes(micField)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = multierror.Append(err, message.Release()).ErrorOrNil()
	}()

	token, err := c.ctx.GetMIC(gssapi.GSS_C_QOP_DEFAULT, message)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = multierror.Append(err, token.Release()).ErrorOrNil()
	}()

	return token.Bytes(), nil
}

// DeleteSecContext is called by the ssh.Client to tear down any active
// security context.
func (c *Client) DeleteSecContext() (err error) {
	err = c.ctx.DeleteSecContext()
	c.ctx = c.lib.GSS_C_NO_CONTEXT

	return
}

// Server implements the ssh.GSSAPIServer interface.
type Server struct {
	strict bool

	lib *gssapi.Lib
	ctx *gssapi.CtxId

	logger logr.Logger
}

// NewServer returns a new Server.
func NewServer(options ...Option[Server]) (s *Server, err error) {
	s = &Server{
		strict: true,
		logger: logr.Discard(),
	}

	for _, option := range options {
		if err = option(s); err != nil {
			return nil, err
		}
	}

	s.lib, err = gssapi.Load(nil)

	return
}

// Close deletes any active security context and unloads any underlying
// libraries as necessary.
func (s *Server) Close() error {
	return multierror.Append(s.DeleteSecContext(), s.lib.Unload())
}

// AcceptSecContext is called by the ssh.ServerConn to accept and advance the
// security context.
//
//nolint:funlen
func (s *Server) AcceptSecContext(token []byte) (b []byte, srcName string, cont bool, err error) {
	var cred *gssapi.CredId

	// equivalent of GSSAPIStrictAcceptorCheck
	if s.strict { //nolint:nestif
		hostname, err := osHostname()
		if err != nil {
			return nil, "", false, err
		}

		buffer, err := s.lib.MakeBufferString("host@" + hostname)
		if err != nil {
			return nil, "", false, err
		}

		defer func() {
			err = multierror.Append(err, buffer.Release()).ErrorOrNil()
		}()

		service, err := buffer.Name(s.lib.GSS_C_NT_HOSTBASED_SERVICE)
		if err != nil {
			return nil, "", false, err
		}

		defer func() {
			err = multierror.Append(err, service.Release()).ErrorOrNil()
		}()

		oids, err := s.lib.MakeOIDSet(s.lib.GSS_MECH_KRB5)
		if err != nil {
			return nil, "", false, err
		}

		defer func() {
			err = multierror.Append(err, oids.Release()).ErrorOrNil()
		}()

		cred, _, _, err = s.lib.AcquireCred(service, gssapi.GSS_C_INDEFINITE, oids, gssapi.GSS_C_ACCEPT)
		if err != nil {
			return nil, "", false, err
		}

		defer func() {
			err = multierror.Append(err, cred.Release()).ErrorOrNil()
		}()
	} else {
		cred = s.lib.GSS_C_NO_CREDENTIAL
	}

	input, err := s.lib.MakeBufferBytes(token)
	if err != nil {
		return nil, "", false, err
	}

	defer func() {
		err = multierror.Append(err, input.Release()).ErrorOrNil()
	}()

	//nolint:dogsled
	ctx, name, _, output, _, _, _, err := s.lib.AcceptSecContext(s.ctx, cred, input, s.lib.GSS_C_NO_CHANNEL_BINDINGS)
	if err != nil && !s.lib.LastStatus.Major.ContinueNeeded() {
		return nil, "", false, err
	}

	defer func() {
		err = multierror.Append(err, name.Release(), output.Release()).ErrorOrNil()
	}()

	s.ctx = ctx

	return output.Bytes(), name.String(), s.lib.LastStatus.Major.ContinueNeeded(), nil
}

// VerifyMIC is called by the ssh.ServerConn to authenticate the user using
// the negotiated security context.
func (s *Server) VerifyMIC(micField, micToken []byte) (err error) {
	message, err := s.lib.MakeBufferBytes(micField)
	if err != nil {
		return nil
	}

	defer func() {
		err = multierror.Append(err, message.Release()).ErrorOrNil()
	}()

	token, err := s.lib.MakeBufferBytes(micToken)
	if err != nil {
		return nil
	}

	defer func() {
		err = multierror.Append(err, token.Release()).ErrorOrNil()
	}()

	_, err = s.ctx.VerifyMIC(message, token)

	return err
}

// DeleteSecContext is called by the ssh.ServerConn to tear down any active
// security context.
func (s *Server) DeleteSecContext() (err error) {
	err = s.ctx.DeleteSecContext()
	s.ctx = s.lib.GSS_C_NO_CONTEXT

	return
}
