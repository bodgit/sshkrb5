// +build windows

package sshkrb5

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	whoami, err := testNewClient(t)
	assert.Nil(t, err)
	assert.Equal(t, "test", whoami)
}

func TestNewClientWithCredentials(t *testing.T) {
	whoami, err := testNewClientWithCredentials(t)
	assert.Nil(t, err)
	assert.Equal(t, "test", whoami)
}

func TestNewClientWithKeytab(t *testing.T) {
	_, err := testNewClientWithKeytab(t)
	assert.Equal(t, errNotSupported, err)
}
