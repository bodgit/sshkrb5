package sshkrb5_test

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/bodgit/sshkrb5"
	multierror "github.com/hashicorp/go-multierror"
	"golang.org/x/crypto/ssh"
)

func testEnvironmentVariables(t *testing.T) (string, string, string, string, string, string) {
	t.Helper()

	var (
		host, port, realm, username, password, keytab string
		ok                                            bool
	)

	for _, env := range []struct {
		ptr  *string
		name string
	}{
		{
			&host,
			"SSH_HOST",
		},
		{
			&port,
			"SSH_PORT",
		},
		{
			&realm,
			"SSH_REALM",
		},
		{
			&username,
			"SSH_USERNAME",
		},
		{
			&password,
			"SSH_PASSWORD",
		},
		{
			&keytab,
			"SSH_KEYTAB",
		},
	} {
		if *env.ptr, ok = os.LookupEnv(env.name); !ok {
			t.Fatalf("%s not set", env.name)
		}
	}

	return host, port, realm, username, password, keytab
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

	result, err = testConnection(client, hostname, port, username)

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

	result, err = testConnection(client, hostname, port, username)

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

	result, err = testConnection(client, hostname, port, username)

	return
}

//nolint:nakedret
func testConnection(gssapi ssh.GSSAPIClient, hostname, port, username string) (result string, err error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.GSSAPIWithMICAuthMethod(gssapi, hostname),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}

	var (
		client  *ssh.Client
		session *ssh.Session
		b       []byte
	)

	client, err = ssh.Dial("tcp", net.JoinHostPort(hostname, port), config)
	if err != nil {
		return
	}

	defer func() {
		err = multierror.Append(err, client.Close()).ErrorOrNil()
	}()

	session, err = client.NewSession()
	if err != nil {
		return
	}

	defer func() {
		if nerr := session.Close(); nerr != nil && !errors.Is(nerr, io.EOF) {
			err = multierror.Append(err, nerr).ErrorOrNil()
		}
	}()

	b, err = session.Output("whoami")
	if err != nil {
		return
	}

	result = strings.TrimSpace(string(b))

	return
}
