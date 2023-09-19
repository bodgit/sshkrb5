[![GitHub release](https://img.shields.io/github/v/release/bodgit/sshkrb5)](https://github.com/bodgit/sshkrb5/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/bodgit/sshkrb5/build.yml?branch=main)](https://github.com/bodgit/sshkrb5/actions?query=workflow%3ABuild)
[![Coverage Status](https://coveralls.io/repos/github/bodgit/sshkrb5/badge.svg?branch=main)](https://coveralls.io/github/bodgit/sshkrb5?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/bodgit/sshkrb5)](https://goreportcard.com/report/github.com/bodgit/sshkrb5)
[![GoDoc](https://godoc.org/github.com/bodgit/sshkrb5?status.svg)](https://godoc.org/github.com/bodgit/sshkrb5)
![Go version](https://img.shields.io/badge/Go-1.20-brightgreen.svg)
![Go version](https://img.shields.io/badge/Go-1.19-brightgreen.svg)

# GSSAPI middleware for crypto/ssh

The [github.com/bodgit/sshkrb5](https://godoc.org/github.com/bodgit/sshkrb5)
package implements the `GSSAPIClient` & `GSSAPIServer` interfaces in
[golang.org/x/crypto/ssh](https://godoc.org/golang.org/x/crypto/ssh).

On non-Windows platforms GSSAPI is supported through either
[github.com/jcmturner/gokrb5](https://github.com/jcmturner/gokrb5) or
[github.com/openshift/gssapi](https://github.com/openshift/gssapi). On
Windows, SSPI is supported using
[github.com/alexbrainman/sspi](https://github.com/alexbrainman/sspi).

It has been tested successfully against OpenSSH.

Sample client:

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

Sample server:

```golang
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"

	"github.com/bodgit/sshkrb5"
	"golang.org/x/crypto/ssh"
)

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		panic(err)
	}

	private, err := ssh.ParsePrivateKey(buf.Bytes())
	if err != nil {
		panic(err)
	}

	gssapi, err := sshkrb5.NewServer()
	if err != nil {
		panic(err)
	}
	defer gssapi.Close()

	config := &ssh.ServerConfig{
		GSSAPIWithMICConfig: &ssh.GSSAPIWithMICConfig{
			AllowLogin: func(c ssh.ConnMetadata, name string) (*ssh.Permissions, error) {
				return nil, nil
			},
			Server: gssapi,
		},
	}

	config.AddHostKey(private)

	listener, err := net.Listen("tcp", "0.0.0.0:22")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}

			_, chans, reqs, err := ssh.NewServerConn(conn, config)
			if err != nil {
				continue
			}

			go ssh.DiscardRequests(reqs)
			go handleChannels(chans)
		}
	}()
}

func handleChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	if t := newChannel.ChannelType(); t != "session" {
		_ = newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))

		return
	}

	_, requests, err := newChannel.Accept()
	if err != nil {
		return
	}

	go ssh.DiscardRequests(requests)
}
```
