package providers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"golang.org/x/oauth2/jws"

	"github.com/golang/glog"
)

type BatonProvider struct {
	*ProviderData
	KeysURL   *url.URL
	certCache *certCache
}

func NewBatonProvider(p *ProviderData) *BatonProvider {
	p.ProviderName = "Baton"
	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "baton-staging.qutics.com",
			Path:   "/oauth2/authorize_scopes",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "baton-staging.qutics.com",
			Path:   "/oauth2/token",
		}
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			Host:   "baton-staging.qutics.com",
			Path:   "/oauth2/whoami",
		}
	}
	if p.Scope == "" {
		p.Scope = "api"
	}
	cc := &certCache{u: p.JWTKeysURL}
	return &BatonProvider{ProviderData: p, certCache: cc}
}

func (p *BatonProvider) GetEmailAddress(s *SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("no access token set")
	}

	keys, err := p.certCache.getKeys()
	if err != nil {
		return "", fmt.Errorf("could not fetch jws signing keys, %w", err)
	}

	var verified bool
	for _, k := range keys {
		if err := jws.Verify(s.AccessToken, k); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return "", errors.New("could not verify jws token against any keys")
	}
	cs, err := jws.Decode("Bearer " + s.AccessToken)
	if err != nil {
		return "", fmt.Errorf("could not decode jws, %w", err)
	}
	if cs.Sub == "" {
		return "", fmt.Errorf("JWT Sub was empty")
	}

	return cs.Sub, nil
}

type certCache struct {
	u *url.URL

	sync.Mutex
	keys map[string]*rsa.PublicKey
}

func (cc *certCache) getKeys() (map[string]*rsa.PublicKey, error) {
	cc.Lock()
	defer cc.Unlock()

	if cc.keys != nil {
		return cc.keys, nil
	}

	res := map[string]*rsa.PublicKey{}

	r, err := http.Get(cc.u.String())
	if err != nil {
		return nil, fmt.Errorf("can't fetch jws keys, %w", err)
	}

	if r.StatusCode != 200 {
		return nil, fmt.Errorf("JWS PublicKey URL retured %v, %v", r.StatusCode, r.Status)
	}

	keyStrs := map[string]string{}
	dec := json.NewDecoder(r.Body)
	err = dec.Decode(&keyStrs)
	if err != nil {
		return nil, fmt.Errorf("unable to read json jws keys,  %v", err)
	}

	for kid, kstr := range keyStrs {
		if glog.V(2) {
			glog.Infof("JWS public key :\n %s", kstr)
		}

		block, _ := pem.Decode([]byte(kstr))

		jwsKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			glog.Warningf("Unable to parse kid %s , jws key %v", kid, err)
			continue
		}

		jwsRSA, ok := jwsKey.(*rsa.PublicKey)
		if !ok {
			glog.Warningf("JWS key must be an RSA public key")
			continue
		}

		res[kid] = jwsRSA
	}

	cc.keys = res
	if glog.V(2) {
		glog.Infof("JWS keys found: %v", cc.keys)
	}

	return res, nil
}
