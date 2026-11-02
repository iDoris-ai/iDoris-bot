//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pkiDir is where generatePKI writes the throwaway CA and Headscale leaf.
// compose.yaml bind-mounts these files, and the directory is gitignored.
const pkiDir = ".pki"

// generatePKI creates a throwaway CA and a Headscale leaf certificate
// (SANs: DNS "headscale", IP 127.0.0.1) in pkiDir and returns a pool trusting
// the CA. Nothing is committed: the directory is removed again on cleanup.
//
//	.pki/ca.pem   CA certificate (mounted into ts-node via SSL_CERT_FILE)
//	.pki/tls.crt  leaf certificate (Headscale tls_cert_path)
//	.pki/tls.key  leaf private key (Headscale tls_key_path)
//
// Files are world-readable on purpose: the key is single-use test material and
// the container user that reads it differs between Docker backends.
func generatePKI(t *testing.T) *x509.CertPool {
	t.Helper()
	if err := os.RemoveAll(pkiDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pkiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkiDir) })

	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "idoris-vpn-it CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "headscale"},
		DNSNames:              []string{"headscale"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}

	write := func(name, blockType string, der []byte) {
		t.Helper()
		b := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
		if err := os.WriteFile(filepath.Join(pkiDir, name), b, 0o644); err != nil { //nolint:gosec // throwaway test key, see doc comment
			t.Fatal(err)
		}
	}
	write("ca.pem", "CERTIFICATE", caDER)
	write("tls.crt", "CERTIFICATE", leafDER)
	write("tls.key", "EC PRIVATE KEY", leafKeyDER)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool
}
