package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/pardot/oidc/discovery"
	"gopkg.in/square/go-jose.v2"
)

type config struct {
	Issuer       string
	ListenAddr   string
	SAPublicPath string
}

func main() {
	cfg := config{
		ListenAddr:   "0.0.0.0:8080",
		SAPublicPath: "/etc/kubernetes/pki/sa.pub", // kubeadm default
	}

	flag.StringVar(&cfg.Issuer, "issuer", cfg.Issuer, "The OIDC issuer URL we are served at. Used as base URL for discovery (required)")
	flag.StringVar(&cfg.SAPublicPath, "service-account-public-key-file", cfg.SAPublicPath, "Path to the SA signer _public_ key file (usually kube-apiserver --service-account-key-file flag value")
	flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "Address to listen for requests on")
	flag.Parse()

	if cfg.Issuer == "" || cfg.ListenAddr == "" || cfg.SAPublicPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	mux := http.NewServeMux()

	// do an initial key load to make sure it'll work, and work out the algs we
	// deal with. We re-load it periodically, in case it's rolled out on us
	if _, err := loadKeysFromFile(cfg.SAPublicPath); err != nil {
		log.Fatalf("failed to load keyset: %v", err)
	}

	ks := &staticKeysource{path: cfg.SAPublicPath}
	mux.Handle("/.well-known/openid-keys", discovery.NewKeysHandler(ks, 1*time.Minute))

	md := discovery.ProviderMetadata{
		Issuer:                           cfg.Issuer,
		JWKSURI:                          cfg.Issuer + "/.well-known/openid-keys",
		IDTokenSigningAlgValuesSupported: []string{string(jose.RS256), string(jose.ES256)},
		// These aren't used, but are required to meet spec so serve up some
		// data
		AuthorizationEndpoint:  cfg.Issuer + "/unused",
		ResponseTypesSupported: []string{"id_token"},
		SubjectTypesSupported:  []string{"public"},
		GrantTypesSupported:    []string{"implicit"},
	}

	ch, err := discovery.NewConfigurationHandler(&md)
	if err != nil {
		log.Fatalf("creating configuration handler: %v", err)
	}
	mux.Handle("/.well-known/openid-configuration", ch)

	mux.HandleFunc("/_health", func(w http.ResponseWriter, r *http.Request) {
		if ks.lastErr != nil {
			http.Error(w, "key read failure", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "OK")
	})

	log.Printf("Serving at %s", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
		log.Fatalf("serving: %v", err)
	}
}

var _ discovery.KeySource = (*staticKeysource)(nil)

type staticKeysource struct {
	path    string
	lastErr error
}

func (s *staticKeysource) PublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	// the handler implentation does basic caching, so just re-read here
	k, err := loadKeysFromFile(s.path)
	if err != nil {
		s.lastErr = err
		return nil, err
	}

	// reset error, we're in OK state now
	s.lastErr = nil
	return &k, nil
}

func loadKeysFromFile(path string) (jose.JSONWebKeySet, error) {
	jwks := jose.JSONWebKeySet{}

	raw, err := os.ReadFile(path)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("reading %s: %v", path, err)
	}

	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" && block.Type != "EC PRIVATE KEY" {
			return jose.JSONWebKeySet{}, fmt.Errorf("non public key block type %s found in %s", block.Type, path)
		}

		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return jose.JSONWebKeySet{}, fmt.Errorf("parsing public key: %v", err)
		}

		var alg jose.SignatureAlgorithm
		switch parsed.(type) {
		case *rsa.PublicKey:
			alg = jose.RS256
		case *ecdsa.PublicKey:
			alg = jose.ES256
		default:
			return jose.JSONWebKeySet{}, fmt.Errorf("invalid public key type: %T", parsed)
		}

		// generate a stable identifier we can refer to this key across runs with
		h := sha256.New()
		h.Write(block.Bytes)
		fp := fmt.Sprintf("%x", h.Sum(nil))

		jk := jose.JSONWebKey{
			Key:       parsed,
			KeyID:     fp,
			Use:       "sig",
			Algorithm: string(alg),
		}
		if !jk.Valid() {
			return jose.JSONWebKeySet{}, fmt.Errorf("internal error - invalid JWK generated")
		}

		jwks.Keys = append(jwks.Keys, jk)

		raw = rest
	}

	return jwks, nil
}
