// +build !windows,!apcera

package sshkrb5

import (
	"errors"
	"os"
	"os/user"
	"strings"

	multierror "github.com/hashicorp/go-multierror"
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

// Client implements the ssh.GSSAPIClient interface.
type Client struct {
	client *client.Client
	key    types.EncryptionKey
}

func loadCache() (*credentials.CCache, error) {

	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	path := "/tmp/krb5cc_" + u.Uid

	if env, ok := os.LookupEnv("KRB5CCNAME"); ok && strings.HasPrefix(env, "FILE:") {
		path = strings.SplitN(env, ":", 2)[1]
	}

	cache, err := credentials.LoadCCache(path)
	if err != nil {
		return nil, err
	}

	return cache, nil
}

func findFile(env string, try []string) (string, error) {
	path, ok := os.LookupEnv(env)
	if ok {
		if _, err := os.Stat(path); err != nil {
			return "", err
		}
		return path, nil
	}

	var errs error
	for _, t := range try {
		_, err := os.Stat(t)
		if err != nil {
			multierror.Append(errs, err)
			if os.IsNotExist(err) {
				continue
			}
			return "", errs
		}
		return t, nil
	}

	return "", errs
}

func loadConfig() (*config.Config, error) {

	path, err := findFile("KRB5_CONFIG", []string{"/etc/krb5.conf"})
	if err != nil {
		return nil, err
	}
	return config.Load(path)
}

// NewClient returns a new Client using the current user.
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

// NewClientWithCredentials returns a new Client using the provided
// credentials.
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

// NewClientWithKeytab returns a new Client using the provided keytab.
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

// Close deletes any active security context and unloads any underlying
// libraries as necessary.
func (c *Client) Close() error {
	err := c.DeleteSecContext()
	c.client.Destroy()
	return err
}

// InitSecContext is called by the ssh.Client to initialise or advance the
// security context.
func (c *Client) InitSecContext(target string, token []byte, isGSSDelegCreds bool) ([]byte, bool, error) {
	gssapiFlags := []int{
		gssapi.ContextFlagMutual,
		gssapi.ContextFlagInteg,
	}
	if isGSSDelegCreds {
		gssapiFlags = append(gssapiFlags, gssapi.ContextFlagDeleg)
	}

	switch token {
	case nil:
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

		return b, true, nil
	default:
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

		return nil, false, nil
	}
}

// GetMIC is called by the ssh.Client to authenticate the user using the
// negotiated security context.
func (c *Client) GetMIC(micField []byte) ([]byte, error) {

	token, err := gssapi.NewInitiatorMICToken(micField, c.key)
	if err != nil {
		return nil, err
	}

	b, err := token.Marshal()
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DeleteSecContext is called by the ssh.Client to tear down any active
// security context.
func (c *Client) DeleteSecContext() error {
	return nil
}
