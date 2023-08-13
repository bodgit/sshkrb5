package sshkrb5_test

import (
	"net"
	"os"
	"strings"
	"testing"

	"github.com/bodgit/sshkrb5"
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

func testNewClient(t *testing.T) (string, error) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test")
	}

	//nolint:dogsled
	hostname, port, _, username, _, _ := testEnvironmentVariables(t)

	client, err := sshkrb5.NewClient()
	if err != nil {
		return "", err
	}
	defer client.Close()

	return testConnection(client, hostname, port, username)
}

func testNewClientWithCredentials(t *testing.T) (string, error) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test")
	}

	hostname, port, realm, username, password, _ := testEnvironmentVariables(t)

	client, err := sshkrb5.NewClientWithCredentials(realm, username, password)
	if err != nil {
		return "", err
	}
	defer client.Close()

	return testConnection(client, hostname, port, username)
}

func testNewClientWithKeytab(t *testing.T) (string, error) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test")
	}

	hostname, port, realm, username, _, keytab := testEnvironmentVariables(t)

	client, err := sshkrb5.NewClientWithKeytab(realm, username, keytab)
	if err != nil {
		return "", err
	}
	defer client.Close()

	return testConnection(client, hostname, port, username)
}

func testConnection(gssapi ssh.GSSAPIClient, hostname, port, username string) (string, error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.GSSAPIWithMICAuthMethod(gssapi, hostname),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(hostname, port), config)
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	b, err := session.Output("whoami")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(b)), nil
}
