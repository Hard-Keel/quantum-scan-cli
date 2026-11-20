package main

import (
	"crypto/ecdh"
	"crypto/rsa"
	"crypto/rand"
	"crypto/tls"
)

func setup() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	curve := ecdh.X25519()
	cfg := &tls.Config{MinVersion: tls.VersionTLS10}
	_, _, _ = key, curve, cfg
}
