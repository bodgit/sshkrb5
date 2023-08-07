//go:build !windows && apcera
// +build !windows,apcera

package sshkrb5_test

import (
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
	_, err := testNewClientWithCredentials(t)
	assert.Equal(t, sshkrb5.ErrNotSupported, err)
}

func TestNewClientWithKeytab(t *testing.T) {
	t.Parallel()
	_, err := testNewClientWithKeytab(t)
	assert.Equal(t, sshkrb5.ErrNotSupported, err)
}

func TestNewServer(t *testing.T) {
	t.Parallel()

	if err := testNewServer(t); err != nil {
		t.Fatal(err)
	}
}
