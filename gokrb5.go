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

// WithConfig sets the configuration in the Client.
func WithConfig[T Client](config string) Option[T] {
	return func(a *T) error {
		if x, ok := any(a).(*Client); ok {
			x.config = config
		}

		return nil
	}
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
			x.keytab = nil
		}

		return nil
	}
}

// WithKeytab sets the keytab path in either a Client or Server.
func WithKeytab[T Client | Server](keytab string) Option[T] {
	return func(a *T) error {
		switch x := any(a).(type) {
		case *Client:
			x.keytab = &keytab
			x.password = ""
		case *Server:
			x.keytab = keytab
		}

		return nil
	}
}

// Client implements the ssh.GSSAPIClient interface.
type Client struct {
	config   string
	domain   string
	username string
	password string
	keytab   *string

	initiator *wrapper.Initiator

	logger logr.Logger
}

func (c *Client) usePassword() bool {
	return c.domain != "" && c.username != "" && c.password != ""
}

func (c *Client) useKeytab() bool {
	return c.domain != "" && c.username != "" && c.keytab != nil
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

	initiatorOptions := []wrapper.Option[wrapper.Initiator]{
		wrapper.WithConfig(c.config),
		wrapper.WithLogger[wrapper.Initiator](c.logger),
	}

	switch {
	case c.usePassword():
		//nolint:lll
		initiatorOptions = append(initiatorOptions, wrapper.WithDomain(c.domain), wrapper.WithUsername(c.username), wrapper.WithPassword(c.password))
	case c.useKeytab():
		//nolint:lll
		initiatorOptions = append(initiatorOptions, wrapper.WithDomain(c.domain), wrapper.WithUsername(c.username), wrapper.WithKeytab[wrapper.Initiator](*c.keytab))
	default:
		c.logger.Info("using default session")
	}

	if c.initiator, err = wrapper.NewInitiator(initiatorOptions...); err != nil {
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
	strict bool
	keytab string

	acceptor *wrapper.Acceptor

	logger logr.Logger
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
		wrapper.WithKeytab[wrapper.Acceptor](s.keytab),
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
