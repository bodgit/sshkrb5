//go:build !windows && !apcera
// +build !windows,!apcera

package sshkrb5_test

import (
	"testing"

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
	whoami, err := testNewClientWithKeytab(t)
	assert.Nil(t, err)
	assert.Equal(t, "test", whoami)
}
