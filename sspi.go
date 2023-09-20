//go:build windows
// +build windows

package sshkrb5

import (
	"strings"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/kerberos"
	"github.com/go-logr/logr"
	multierror "github.com/hashicorp/go-multierror"
)

// WithConfig sets the configuration in the Client.
func WithConfig[T Client](_ string) Option[T] {
	return unsupportedOption[T]
}

// WithDomain sets the Kerberos domain in the Client.
func WithDomain[T Client](domain string) Option[T] {
	return func(a *T) error {
		if x, ok := any(a).(*Client); ok {
			x.domain = domain
		}

		return nil
	}
}

// WithUsername sets the username in the Client.
func WithUsername[T Client](username string) Option[T] {
	return func(a *T) error {
		if x, ok := any(a).(*Client); ok {
			x.username = username
		}

		return nil
	}
}

// WithPassword sets the password in the Client.
func WithPassword[T Client](password string) Option[T] {
	return func(a *T) error {
		if x, ok := any(a).(*Client); ok {
			x.password = password
		}

		return nil
	}
}

// WithKeytab sets the keytab path in either a Client or Server.
func WithKeytab[T Client | Server](_ string) Option[T] {
	return unsupportedOption[T]
}

// Client implements the ssh.GSSAPIClient interface.
type Client struct {
	domain   string
	username string
	password string

	creds *sspi.Credentials
	ctx   *kerberos.ClientContext

	logger logr.Logger
}

func (c *Client) usePassword() bool {
	return c.domain != "" && c.username != "" && c.password != ""
}

// NewClient returns a new Client using the current user.
func NewClient(options ...Option[Client]) (*Client, error) {
	c := &Client{
		logger: logr.Discard(),
	}

	var err error

	for _, option := range options {
		if err = option(c); err != nil {
			return nil, err
		}
	}

	if c.usePassword() {
		c.creds, err = kerberos.AcquireUserCredentials(c.domain, c.username, c.password)
	} else {
		c.creds, err = kerberos.AcquireCurrentUserCredentials()
	}

	if err != nil {
		return nil, err
	}

	return c, nil
}

// Close deletes any active security context and unloads any underlying
// libraries as necessary.
func (c *Client) Close() error {
	return multierror.Append(c.DeleteSecContext(), c.creds.Release()).ErrorOrNil()
}

// InitSecContext is called by the ssh.Client to initialise or advance the
// security context.
func (c *Client) InitSecContext(target string, token []byte, isGSSDelegCreds bool) ([]byte, bool, error) {
	var (
		completed bool
		output    []byte
		err       error
	)

	if len(token) == 0 {
		sspiFlags := uint32(sspi.ISC_REQ_MUTUAL_AUTH | sspi.ISC_REQ_CONNECTION | sspi.ISC_REQ_INTEGRITY)
		if isGSSDelegCreds {
			sspiFlags |= sspi.ISC_REQ_DELEGATE
		}

		//nolint:lll
		c.ctx, completed, output, err = kerberos.NewClientContextWithFlags(c.creds, strings.ReplaceAll(target, "@", "/"), sspiFlags)
		if err != nil {
			return nil, false, err
		}
	} else {
		completed, output, err = c.ctx.Update(token)
	}

	if err != nil {
		return nil, false, err
	}

	return output, !completed, nil
}

// GetMIC is called by the ssh.Client to authenticate the user using the
// negotiated security context.
func (c *Client) GetMIC(micField []byte) ([]byte, error) {
	return c.ctx.MakeSignature(micField, 0, 0)
}

// DeleteSecContext is called by the ssh.Client to tear down any active
// security context.
func (c *Client) DeleteSecContext() (err error) {
	if c.ctx != nil {
		err = c.ctx.Release()
		c.ctx = nil
	}

	return
}

// Server implements the ssh.GSSAPIServer interface.
type Server struct {
	creds *sspi.Credentials
	ctx   *kerberos.ServerContext

	logger logr.Logger
}

// NewServer returns a new Server.
func NewServer(options ...Option[Server]) (*Server, error) {
	s := &Server{
		logger: logr.Discard(),
	}

	for _, option := range options {
		if err := option(s); err != nil {
			return nil, err
		}
	}

	creds, err := kerberos.AcquireServerCredentials("")
	if err != nil {
		return nil, err
	}

	s.creds = creds

	return s, nil
}

// Close deletes any active security context and unloads any underlying
// libraries as necessary.
func (s *Server) Close() error {
	return multierror.Append(s.DeleteSecContext(), s.creds.Release()).ErrorOrNil()
}

// AcceptSecContext is called by the ssh.ServerConn to accept and advance the
// security context.
func (s *Server) AcceptSecContext(token []byte) ([]byte, string, bool, error) {
	var (
		completed bool
		output    []byte
		err       error
	)

	if s.ctx == nil {
		s.ctx, completed, output, err = kerberos.NewServerContext(s.creds, token)
	} else {
		completed, output, err = s.ctx.Update(token)
	}

	if err != nil {
		return nil, "", false, err
	}

	var username string

	if completed {
		if username, err = s.ctx.GetUsername(); err != nil {
			return nil, "", false, err
		}
	}

	return output, username, !completed, nil
}

// VerifyMIC is called by the ssh.ServerConn to authenticate the user using
// the negotiated security context.
func (s *Server) VerifyMIC(micField, micToken []byte) error {
	_, err := s.ctx.VerifySignature(micField, micToken, 0)

	return err
}

// DeleteSecContext is called by the ssh.ServerConn to tear down any active
// security context.
func (s *Server) DeleteSecContext() (err error) {
	if s.ctx != nil {
		err = s.ctx.Release()
		s.ctx = nil
	}

	return
}
