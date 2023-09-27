//go:build !windows && !apcera
// +build !windows,!apcera

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

	whoami, err := testNewClientWithCredentials(t)
	if err != nil {
		t.Fatal(err)
	}

	assert.Regexp(t, regexp.MustCompile(`\btest$`), whoami)
}

func TestNewClientWithKeytab(t *testing.T) {
	t.Parallel()

	whoami, err := testNewClientWithKeytab(t)
	if err != nil {
		t.Fatal(err)
	}

	assert.Regexp(t, regexp.MustCompile(`\btest$`), whoami)
}

func TestNewClientWithConfig(t *testing.T) {
	t.Parallel()

	_, err := sshkrb5.NewClient(sshkrb5.WithConfig(""))
	assert.Nil(t, err)
}

func TestNewServer(t *testing.T) {
	t.Parallel()

	if err := testNewServer(t); err != nil {
		t.Fatal(err)
	}
}
