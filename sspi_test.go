//go:build windows
// +build windows

package sshkrb5_test

import (
	"os/user"
	"regexp"
	"testing"

	"github.com/bodgit/sshkrb5"
	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	t.Parallel()

	whoami, err := testNewClient(t)
	if err != nil {
		t.Fatal(err)
	}

	assert.Regexp(t, regexp.MustCompile(`\btest$`), whoami)
}

func TestNewClientWithCredentials(t *testing.T) {
	t.Parallel()

	whoami, err := testNewClientWithCredentials(t)
	if err != nil {
		t.Fatal(err)
	}

	assert.Regexp(t, regexp.MustCompile(`\btest$`), whoami)
}

func TestNewClientWithKeytab(t *testing.T) {
	t.Parallel()
	_, err := testNewClientWithKeytab(t)
	assert.Equal(t, sshkrb5.ErrNotSupported, err)
}

func TestNewServer(t *testing.T) {
	t.Parallel()

	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	if u.Username != `NT AUTHORITY\SYSTEM` {
		t.Skip("not running as system account")
	}

	if err := testNewServer(t); err != nil {
		t.Fatal(err)
	}
}
