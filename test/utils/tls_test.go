package utils_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ratelimit/src/utils"
)

func writeTestCA(t *testing.T) (string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return caFile, cert
}

func TestLoadCertPoolClientCAExcludesSystemRoots(t *testing.T) {
	caFile, caCert := writeTestCA(t)

	pool, err := utils.LoadCertPool(caFile, utils.ClientCA)
	require.NoError(t, err)

	// Only the provided CA must be trusted for client certs
	expected := x509.NewCertPool()
	expected.AddCert(caCert)
	assert.True(t, pool.Equal(expected))
}

func TestLoadCertPoolServerCAIncludesSystemRoots(t *testing.T) {
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("system cert pool not available: %v", err)
	}
	caFile, caCert := writeTestCA(t)

	pool, err := utils.LoadCertPool(caFile, utils.ServerCA)
	require.NoError(t, err)

	// The provided CA is appended to the system roots
	expected := systemPool.Clone()
	expected.AddCert(caCert)
	assert.True(t, pool.Equal(expected))
}

func TestLoadCertPoolInvalidFile(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(caFile, []byte("not a certificate"), 0o600))

	_, err := utils.LoadCertPool(caFile, utils.ClientCA)
	assert.Error(t, err)
	_, err = utils.LoadCertPool(filepath.Join(t.TempDir(), "missing.crt"), utils.ClientCA)
	assert.Error(t, err)
}
