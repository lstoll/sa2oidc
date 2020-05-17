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
	"io/ioutil"
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
	flag.StringVar(&cfg.SAPublicPath, "service-account-public-key-file", cfg.SAPublicPath, "Path to the SA signer _public_ key file (usually kube-apiserver `service-account-key-file` flag value")
	flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "Address to listen for requests on")
	flag.Parse()

	if cfg.Issuer == "" || cfg.ListenAddr == "" || cfg.SAPublicPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	mux := http.NewServeMux()

	raw, err := ioutil.ReadFile(cfg.SAPublicPath)
	if err != nil {
		log.Fatalf("reading %s: %v", cfg.SAPublicPath, err)
	}

	jwks := jose.JSONWebKeySet{}
	algset := map[string]struct{}{}

	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" && block.Type != "EC PRIVATE KEY" {
			log.Printf("warn - non publc key block found in %s, skipping it", cfg.SAPublicPath)
		}

		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatalf("parsing public key: %v", err)
		}

		var alg jose.SignatureAlgorithm
		switch parsed.(type) {
		case *rsa.PublicKey:
			alg = jose.RS256
			algset[string(jose.RS256)] = struct{}{}
		case *ecdsa.PublicKey:
			alg = jose.ES256
			algset[string(jose.ES256)] = struct{}{}
		default:
			log.Fatalf("invalid public key type: %T", parsed)
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
			log.Fatal("internal error - invalid JWK generated")
		}

		jwks.Keys = append(jwks.Keys, jk)

		raw = rest
	}
	if len(jwks.Keys) < 1 {
		log.Fatalf("no keys loaded from %s", cfg.SAPublicPath)
	}

	ks := &staticKeysource{jwks}
	mux.Handle("/.well-known/openid-keys", discovery.NewKeysHandler(ks, 1*time.Minute))

	var algs []string
	for k := range algset {
		algs = append(algs, k)
	}

	md := discovery.ProviderMetadata{
		Issuer:                           cfg.Issuer,
		JWKSURI:                          cfg.Issuer + "/.well-known/openid-keys",
		IDTokenSigningAlgValuesSupported: algs,
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

	log.Printf("Serving at %s", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
		log.Fatalf("serving: %v", err)
	}
}

var _ discovery.KeySource = (*staticKeysource)(nil)

type staticKeysource struct {
	keys jose.JSONWebKeySet
}

func (s *staticKeysource) PublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	return &s.keys, nil
}
