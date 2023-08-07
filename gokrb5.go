//go:build !windows && !apcera
// +build !windows,!apcera

package sshkrb5

import (
	wrapper "github.com/bodgit/gssapi"
	"github.com/go-logr/logr"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Client implements the ssh.GSSAPIClient interface.
type Client struct {
	initiator *wrapper.Initiator
}

// NewClient returns a new Client using the current user.
func NewClient() (*Client, error) {
	c := new(Client)

	var err error

	if c.initiator, err = wrapper.NewInitiator(); err != nil {
		return nil, err
	}

	return c, nil
}

// NewClientWithCredentials returns a new Client using the provided
// credentials.
func NewClientWithCredentials(domain, username, password string) (*Client, error) {
	c := new(Client)

	var err error

	//nolint:lll
	if c.initiator, err = wrapper.NewInitiator(wrapper.WithDomain(domain), wrapper.WithUsername(username), wrapper.WithPassword(password)); err != nil {
		return nil, err
	}

	return c, nil
}

// NewClientWithKeytab returns a new Client using the provided keytab.
func NewClientWithKeytab(domain, username, path string) (*Client, error) {
	c := new(Client)

	var err error

	//nolint:lll
	if c.initiator, err = wrapper.NewInitiator(wrapper.WithDomain(domain), wrapper.WithUsername(username), wrapper.WithKeytab[wrapper.Initiator](path)); err != nil {
		return nil, err
	}

	return c, nil
}

// Close deletes any active security context and unloads any underlying
// libraries as necessary.
func (c *Client) Close() error {
	return multierror.Append(c.DeleteSecContext(), c.initiator.Close()).ErrorOrNil()
}

// InitSecContext is called by the ssh.Client to initialise or advance the
// security context.
func (c *Client) InitSecContext(target string, token []byte, isGSSDelegCreds bool) ([]byte, bool, error) {
	flags := gssapi.ContextFlagMutual | gssapi.ContextFlagInteg
	if isGSSDelegCreds {
		flags |= gssapi.ContextFlagDeleg
	}

	return c.initiator.Initiate(target, flags, token)
}

// GetMIC is called by the ssh.Client to authenticate the user using the
// negotiated security context.
func (c *Client) GetMIC(micField []byte) ([]byte, error) {
	return c.initiator.MakeSignature(micField)
}

// DeleteSecContext is called by the ssh.Client to tear down any active
// security context.
func (c *Client) DeleteSecContext() error {
	return nil
}

// Server implements the ssh.GSSAPIServer interface.
type Server struct {
	strict   bool
	logger   logr.Logger
	acceptor *wrapper.Acceptor
}

// NewServer returns a new Server.
func NewServer(options ...Option[Server]) (*Server, error) {
	s := &Server{
		strict: true,
		logger: logr.Discard(),
	}

	for _, option := range options {
		if err := option(s); err != nil {
			return nil, err
		}
	}

	acceptorOptions := []wrapper.Option[wrapper.Acceptor]{
		wrapper.WithLogger[wrapper.Acceptor](s.logger),
	}

	if s.strict {
		hostname, err := osHostname()
		if err != nil {
			return nil, err
		}

		principal := types.NewPrincipalName(nametype.KRB_NT_SRV_HST, "host/"+hostname)

		acceptorOptions = append(acceptorOptions, wrapper.WithServicePrincipal(&principal))
	}

	var err error

	if s.acceptor, err = wrapper.NewAcceptor(acceptorOptions...); err != nil {
		return nil, err
	}

	return s, nil
}

// Close deletes any active security context and unloads any underlying
// libraries as necessary.
func (s *Server) Close() error {
	return s.DeleteSecContext()
}

// AcceptSecContext is called by the ssh.ServerConn to accept and advance the
// security context.
func (s *Server) AcceptSecContext(token []byte) ([]byte, string, bool, error) {
	output, cont, err := s.acceptor.Accept(token)

	return output, s.acceptor.PeerName(), cont, err
}

// VerifyMIC is called by the ssh.ServerConn to authenticate the user using
// the negotiated security context.
func (s *Server) VerifyMIC(micField, micToken []byte) error {
	return s.acceptor.VerifySignature(micField, micToken)
}

// DeleteSecContext is called by the ssh.ServerConn to tear down any active
// security context.
func (s *Server) DeleteSecContext() error {
	return nil
}
