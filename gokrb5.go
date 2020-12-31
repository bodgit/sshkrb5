// +build !windows,!apcera

package sshkrb5

import (
	"errors"
	"os"
	"os/user"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

type clientState int

const (
	clientStateInitial clientState = iota
	clientStateMutual
	clientStateReady
)

type Client struct {
	client *client.Client
	key    types.EncryptionKey
	state  clientState
}

func loadCache() (*credentials.CCache, error) {

	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	path := "/tmp/krb5cc_" + u.Uid

	env := os.Getenv("KRB5CCNAME")
	if strings.HasPrefix(env, "FILE:") {
		path = strings.SplitN(env, ":", 2)[1]
	}

	cache, err := credentials.LoadCCache(path)
	if err != nil {
		return nil, err
	}

	return cache, nil
}

func loadConfig() (*config.Config, error) {

	path := os.Getenv("KRB5_CONFIG")
	_, err := os.Stat(path)
	if err != nil {

		// List of candidates to try
		try := []string{"/etc/krb5.conf"}

		for _, t := range try {
			_, err := os.Stat(t)
			if err == nil {
				path = t
				break
			}
		}
	}

	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func NewClient() (*Client, error) {

	c := new(Client)

	cache, err := loadCache()
	if err != nil {
		return nil, err
	}

	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}

	if c.client, err = client.NewFromCCache(cache, cfg, client.DisablePAFXFAST(true)); err != nil {
		return nil, err
	}

	return c, nil
}

func NewClientWithCredentials(domain, username, password string) (*Client, error) {

	c := new(Client)

	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}

	c.client = client.NewWithPassword(username, domain, password, cfg, client.DisablePAFXFAST(true))

	if err = c.client.Login(); err != nil {
		return nil, err
	}

	return c, nil
}

func NewClientWithKeytab(domain, username, path string) (*Client, error) {

	c := new(Client)

	kt, err := keytab.Load(path)
	if err != nil {
		return nil, err
	}

	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}

	c.client = client.NewWithKeytab(username, domain, kt, cfg, client.DisablePAFXFAST(true))

	if err = c.client.Login(); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Client) InitSecContext(target string, token []byte, isGSSDelegCreds bool) ([]byte, bool, error) {
	gssapiFlags := []int{
		gssapi.ContextFlagMutual,
		gssapi.ContextFlagInteg,
	}
	if isGSSDelegCreds {
		gssapiFlags = append(gssapiFlags, gssapi.ContextFlagDeleg)
	}

	switch c.state {
	case clientStateInitial:
		tkt, key, err := c.client.GetServiceTicket(strings.ReplaceAll(target, "@", "/"))
		if err != nil {
			return nil, false, err
		}

		apreq, err := spnego.NewKRB5TokenAPREQ(c.client, tkt, key, gssapiFlags, []int{flags.APOptionMutualRequired})
		if err != nil {
			return nil, false, err
		}

		if err = apreq.APReq.DecryptAuthenticator(key); err != nil {
			return nil, false, err
		}

		etype, err := crypto.GetEtype(key.KeyType)
		if err != nil {
			return nil, false, err
		}

		// Tweak decrypted authenticator
		if err = apreq.APReq.Authenticator.GenerateSeqNumberAndSubKey(key.KeyType, etype.GetKeyByteSize()); err != nil {
			return nil, false, err
		}

		// Copy the decrypted key now, recreating the AP_REQ will wipe it
		c.key = apreq.APReq.Authenticator.SubKey

		// Recreate the AP_REQ with the tweaked authenticator
		if apreq.APReq, err = messages.NewAPReq(tkt, key, apreq.APReq.Authenticator); err != nil {
			return nil, false, err
		}

		b, err := apreq.Marshal()
		if err != nil {
			return nil, false, err
		}

		c.state = clientStateMutual

		return b, true, nil
	case clientStateMutual:
		var aprep spnego.KRB5Token
		if err := aprep.Unmarshal(token); err != nil {
			return nil, false, err
		}

		if aprep.IsKRBError() {
			return nil, false, errors.New("received Kerberos error")
		}

		if !aprep.IsAPRep() {
			return nil, false, errors.New("didn't receive an AP_REP")
		}

		c.state = clientStateReady

		return nil, false, nil
	case clientStateReady:
		return nil, false, errors.New("FIXME")
	default:
		return nil, false, errors.New("FIXME")
	}
}

func (c *Client) GetMIC(micFiled []byte) ([]byte, error) {

	token, err := gssapi.NewInitiatorMICToken(micFiled, c.key)
	if err != nil {
		return nil, err
	}

	b, err := token.Marshal()
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (c *Client) DeleteSecContext() error {

	c.client.Destroy()

	return nil
}
