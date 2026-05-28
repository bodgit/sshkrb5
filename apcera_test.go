//go:build !windows && apcera
// +build !windows,apcera

package sshkrb5_test

import (
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

	assert.Regexp(t, `\btest$`, whoami)
}

func TestNewClientWithCredentials(t *testing.T) {
	t.Parallel()
	_, err := testNewClientWithCredentials(t)
	assert.ErrorIs(t, err, sshkrb5.ErrNotSupported)
}

func TestNewClientWithKeytab(t *testing.T) {
	t.Parallel()
	_, err := testNewClientWithKeytab(t)
	assert.ErrorIs(t, err, sshkrb5.ErrNotSupported)
}

func TestNewServer(t *testing.T) {
	t.Parallel()

	if err := testNewServer(t); err != nil {
		t.Fatal(err)
	}
}
