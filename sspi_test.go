//go:build windows
// +build windows

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
	whoami, err := testNewClientWithCredentials(t)
	assert.Nil(t, err)
	assert.Equal(t, "test", whoami)
}

func TestNewClientWithKeytab(t *testing.T) {
	t.Parallel()
	_, err := testNewClientWithKeytab(t)
	assert.Equal(t, sshkrb5.ErrNotSupported, err)
}
