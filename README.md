[![GitHub release](https://img.shields.io/github/v/release/bodgit/sshkrb5)](https://github.com/bodgit/sshkrb5/releases)
[![Build Status](https://img.shields.io/github/workflow/status/bodgit/sshkrb5/build)](https://github.com/bodgit/sshkrb5/actions?query=workflow%3Abuild)
[![Coverage Status](https://coveralls.io/repos/github/bodgit/sshkrb5/badge.svg?branch=master)](https://coveralls.io/github/bodgit/sshkrb5?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/bodgit/sshkrb5)](https://goreportcard.com/report/github.com/bodgit/sshkrb5)
[![GoDoc](https://godoc.org/github.com/bodgit/sshkrb5?status.svg)](https://godoc.org/github.com/bodgit/sshkrb5)
![Go version](https://img.shields.io/badge/Go-1.18-brightgreen.svg)
![Go version](https://img.shields.io/badge/Go-1.17-brightgreen.svg)

# GSSAPI middleware for crypto/ssh

The [github.com/bodgit/sshkrb5](https://godoc.org/github.com/bodgit/sshkrb5)
package implements the `GSSAPIClient` & `GSSAPIServer` interfaces in
[golang.org/x/crypto/ssh](https://godoc.org/golang.org/x/crypto/ssh).

```golang
package main

import (
	"net"
	"os"
	"os/user"

	"github.com/bodgit/sshkrb5"
	"golang.org/x/crypto/ssh"
)

func main() {
	hostname := os.Args[1]

	u, err := user.Current()
	if err != nil {
		panic(err)
	}

	gssapi, err := sshkrb5.NewClient()
	if err != nil {
		panic(err)
	}
	defer gssapi.Close()

	config := &ssh.ClientConfig{
		User: u.Username,
		Auth: []ssh.AuthMethod{
			ssh.GSSAPIWithMICAuthMethod(gssapi, hostname),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(hostname, "22"), config)
	if err != nil {
		panic(err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		panic(err)
	}
	defer session.Close()

	b, err := session.Output("whoami")
	if err != nil {
		panic(err)
	}
	os.Stdout.Write(b)
}
```
