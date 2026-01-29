package server

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCipherSuites(t *testing.T) {
	t.Run("empty string returns nil", func(t *testing.T) {
		suites, err := ParseCipherSuites("")
		require.NoError(t, err)
		assert.Nil(t, suites)
	})

	t.Run("single cipher suite", func(t *testing.T) {
		suites, err := ParseCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
		require.NoError(t, err)
		assert.Equal(t, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, suites)
	})

	t.Run("multiple cipher suites", func(t *testing.T) {
		suites, err := ParseCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
		require.NoError(t, err)
		assert.Equal(t, []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		}, suites)
	})

	t.Run("cipher suites with spaces", func(t *testing.T) {
		suites, err := ParseCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 , TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
		require.NoError(t, err)
		assert.Equal(t, []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		}, suites)
	})

	t.Run("unknown cipher suite returns error", func(t *testing.T) {
		_, err := ParseCipherSuites("TLS_UNKNOWN_CIPHER")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown cipher suite")
	})

	t.Run("TLS 1.3 cipher suites", func(t *testing.T) {
		suites, err := ParseCipherSuites("TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256")
		require.NoError(t, err)
		assert.Equal(t, []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		}, suites)
	})

	t.Run("modern cipher suites without CBC", func(t *testing.T) {
		// These are the recommended modern cipher suites that don't use CBC
		modernSuites := []string{
			"TLS_AES_128_GCM_SHA256",
			"TLS_AES_256_GCM_SHA384",
			"TLS_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		}

		for _, suite := range modernSuites {
			t.Run(suite, func(t *testing.T) {
				suites, err := ParseCipherSuites(suite)
				require.NoError(t, err)
				assert.Len(t, suites, 1)
			})
		}
	})
}
