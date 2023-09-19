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
	logger logr.Logger
	creds  *sspi.Credentials
	ctx    *kerberos.ServerContext
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
