package sshkrb5_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/bodgit/sshkrb5"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	multierror "github.com/hashicorp/go-multierror"
	"golang.org/x/crypto/ssh"
)

func testEnvironmentVariables(t *testing.T) (string, string, string, string, string, string) {
	t.Helper()

	var (
		host     string
		port     string
		realm    string
		username string
		password string
		keytab   string
		ok       bool
		errs     *multierror.Error
	)

	for _, env := range []struct {
		ptr      *string
		name     string
		optional bool
	}{
		{
			&host,
			"SSH_HOST",
			false,
		},
		{
			&port,
			"SSH_PORT",
			false,
		},
		{
			&realm,
			"SSH_REALM",
			false,
		},
		{
			&username,
			"SSH_USERNAME",
			false,
		},
		{
			&password,
			"SSH_PASSWORD",
			false,
		},
		{
			&keytab,
			"SSH_KEYTAB",
			runtime.GOOS == "windows",
		},
	} {
		if *env.ptr, ok = os.LookupEnv(env.name); !ok && !env.optional {
			errs = multierror.Append(errs, fmt.Errorf("%s is not set", env.name))
		}
	}

	if errs.ErrorOrNil() != nil {
		t.Fatal(errs)
	}

	return host, port, realm, username, password, keytab
}

func newClient(gssapi ssh.GSSAPIClient, hostname, port, username string) (*ssh.Session, func() error, error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.GSSAPIWithMICAuthMethod(gssapi, hostname),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}

	client, err := ssh.Dial("tcp4", net.JoinHostPort(hostname, port), config)
	if err != nil {
		return nil, nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, nil, multierror.Append(err, client.Close())
	}

	return session, func() (err error) {
		if nerr := session.Close(); nerr != nil && !errors.Is(nerr, io.EOF) {
			err = nerr
		}

		return multierror.Append(err, client.Close()).ErrorOrNil()
	}, nil
}

func testConnectionWhoami(gssapi ssh.GSSAPIClient, hostname, port, username string) (result string, err error) {
	var (
		session  *ssh.Session
		teardown func() error
		b        []byte
	)

	session, teardown, err = newClient(gssapi, hostname, port, username)
	if err != nil {
		return
	}

	defer func() {
		err = multierror.Append(err, teardown()).ErrorOrNil()
	}()

	b, err = session.Output("whoami")
	if err != nil {
		return
	}

	result = strings.TrimSpace(string(b))

	return
}

func testNewClient(t *testing.T) (result string, err error) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test")
	}

	//nolint:dogsled
	hostname, port, _, username, _, _ := testEnvironmentVariables(t)

	var client *sshkrb5.Client

	client, err = sshkrb5.NewClient()
	if err != nil {
		return
	}

	defer func() {
		err = multierror.Append(err, client.Close()).ErrorOrNil()
	}()

	result, err = testConnectionWhoami(client, hostname, port, username)

	return
}

func testNewClientWithCredentials(t *testing.T) (result string, err error) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test")
	}

	hostname, port, realm, username, password, _ := testEnvironmentVariables(t)

	var client *sshkrb5.Client

	client, err = sshkrb5.NewClientWithCredentials(realm, username, password)
	if err != nil {
		return
	}

	defer func() {
		err = multierror.Append(err, client.Close()).ErrorOrNil()
	}()

	result, err = testConnectionWhoami(client, hostname, port, username)

	return
}

func testNewClientWithKeytab(t *testing.T) (result string, err error) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test")
	}

	hostname, port, realm, username, _, keytab := testEnvironmentVariables(t)

	var client *sshkrb5.Client

	client, err = sshkrb5.NewClientWithKeytab(realm, username, keytab)
	if err != nil {
		return
	}

	defer func() {
		err = multierror.Append(err, client.Close()).ErrorOrNil()
	}()

	result, err = testConnectionWhoami(client, hostname, port, username)

	return
}

//nolint:funlen
func newServer(hostname string, logger logr.Logger) (string, func() error, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, err
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return "", nil, err
	}

	private, err := ssh.ParsePrivateKey(buf.Bytes())
	if err != nil {
		return "", nil, err
	}

	options := []sshkrb5.Option[sshkrb5.Server]{
		sshkrb5.WithLogger(logger),
	}

	if runtime.GOOS != "windows" {
		options = append(options, sshkrb5.WithStrictMode(true))
	}

	gssapi, err := sshkrb5.NewServer(options...)
	if err != nil {
		return "", nil, err
	}

	config := &ssh.ServerConfig{
		GSSAPIWithMICConfig: &ssh.GSSAPIWithMICConfig{
			AllowLogin: func(c ssh.ConnMetadata, name string) (*ssh.Permissions, error) {
				return nil, nil //nolint:nilnil
			},
			Server: gssapi,
		},
	}

	config.AddHostKey(private)

	listener, err := net.Listen("tcp4", net.JoinHostPort(hostname, "0"))
	if err != nil {
		return "", nil, multierror.Append(err, gssapi.Close())
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}

			_, chans, reqs, err := ssh.NewServerConn(conn, config)
			if err != nil {
				continue
			}

			go ssh.DiscardRequests(reqs)
			go handleChannels(chans)
		}
	}()

	return strconv.FormatUint(uint64(netip.MustParseAddrPort(listener.Addr().String()).Port()), 10), func() error {
		return multierror.Append(listener.Close(), gssapi.Close()).ErrorOrNil()
	}, nil
}

func handleChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	if t := newChannel.ChannelType(); t != "session" {
		_ = newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))

		return
	}

	_, requests, err := newChannel.Accept()
	if err != nil {
		return
	}

	go ssh.DiscardRequests(requests)
}

func testConnection(gssapi ssh.GSSAPIClient, hostname, port, username string) error {
	_, teardown, err := newClient(gssapi, hostname, port, username)
	if err != nil {
		return err
	}

	return teardown()
}

//nolint:nakedret
func testNewServer(t *testing.T) (err error) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test")
	}

	//nolint:dogsled
	hostname, _, _, username, _, _ := testEnvironmentVariables(t)

	old := sshkrb5.OSHostname
	*sshkrb5.OSHostname = func() (string, error) { //nolint:unparam
		return hostname, nil
	}

	defer func() {
		sshkrb5.OSHostname = old
	}()

	var (
		port     string
		teardown func() error
		client   *sshkrb5.Client
	)

	port, teardown, err = newServer(hostname, testr.New(t))
	if err != nil {
		return
	}

	defer func() {
		err = multierror.Append(err, teardown()).ErrorOrNil()
	}()

	client, err = sshkrb5.NewClient()
	if err != nil {
		return
	}

	defer func() {
		err = multierror.Append(err, client.Close()).ErrorOrNil()
	}()

	err = testConnection(client, hostname, port, username)

	return
}
