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
	assert.Nil(t, err)
	assert.Equal(t, "test", whoami)
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
