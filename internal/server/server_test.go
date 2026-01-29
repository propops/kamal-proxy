package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_Deploying(t *testing.T) {
	target := testTarget(t, func(w http.ResponseWriter, r *http.Request) {})
	server := testServer(t, true)

	testDeployTarget(t, target, server, defaultServiceOptions)

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/", server.HttpPort()))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestServer_DeployingHTTPS(t *testing.T) {
	startDeployment := func(http3Enabled bool) *Server {
		target := testTarget(t, func(w http.ResponseWriter, r *http.Request) {})
		server := testServer(t, http3Enabled)

		certPath, keyPath := prepareTestCertificateFiles(t)
		serviceOptions := defaultServiceOptions
		serviceOptions.TLSEnabled = true
		serviceOptions.TLSCertificatePath = certPath
		serviceOptions.TLSPrivateKeyPath = keyPath
		serviceOptions.TLSRedirect = true

		testDeployTarget(t, target, server, serviceOptions)
		return server
	}

	t.Run("with HTTP/3 enabled", func(t *testing.T) {
		server := startDeployment(true)

		t.Run("http/1.1", func(t *testing.T) {
			resp, err := testRequestUsingHTTP11(t, server)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "HTTP/1.1", resp.Proto)

			assert.Contains(t, resp.Header.Get("Alt-Svc"), "h3")
			assert.Contains(t, resp.Header.Get("Alt-Svc"), fmt.Sprintf(":%d", server.HttpsPort()))
		})

		t.Run("http/2", func(t *testing.T) {
			resp, err := testRequestUsingHTTP2(t, server)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "HTTP/2.0", resp.Proto)

			assert.Contains(t, resp.Header.Get("Alt-Svc"), "h3")
			assert.Contains(t, resp.Header.Get("Alt-Svc"), fmt.Sprintf(":%d", server.HttpsPort()))
		})

		t.Run("http/3", func(t *testing.T) {
			resp, err := testRequestUsingHTTP3(t, server)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "HTTP/3.0", resp.Proto)

			assert.Empty(t, resp.Header.Get("Alt-Svc"))
		})
	})

	t.Run("with HTTP/3 disabled", func(t *testing.T) {
		server := startDeployment(false)

		t.Run("http/1.1", func(t *testing.T) {
			resp, err := testRequestUsingHTTP11(t, server)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "HTTP/1.1", resp.Proto)

			assert.Empty(t, resp.Header.Get("Alt-Svc"))
		})

		t.Run("http/2", func(t *testing.T) {
			resp, err := testRequestUsingHTTP2(t, server)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "HTTP/2.0", resp.Proto)

			assert.Empty(t, resp.Header.Get("Alt-Svc"))
		})

		t.Run("http/3", func(t *testing.T) {
			// Ensure we don't already have a UDP listener for HTTP/3
			addr := fmt.Sprintf(":%d", server.HttpsPort())
			con, err := net.ListenPacket("udp", addr)
			require.NoError(t, err)
			con.Close()
		})
	})
}

// Helpers

func testDeployTarget(tb testing.TB, target *Target, server *Server, serviceOptions ServiceOptions) {
	tb.Helper()
	var result bool
	err := server.commandHandler.Deploy(DeployArgs{
		TargetURLs:        []string{target.Address()},
		DeploymentOptions: defaultDeploymentOptions,
		ServiceOptions:    serviceOptions,
		TargetOptions:     defaultTargetOptions,
	}, &result)

	require.NoError(tb, err)
}

func testRequestUsingHTTP11(tb testing.TB, server *Server) (*http.Response, error) {
	tb.Helper()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return testRequestUsingTransport(server, transport)
}

func testRequestUsingHTTP2(tb testing.TB, server *Server) (*http.Response, error) {
	tb.Helper()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	}

	return testRequestUsingTransport(server, transport)
}

func testRequestUsingHTTP3(tb testing.TB, server *Server) (*http.Response, error) {
	tb.Helper()
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},
	}
	tb.Cleanup(func() { _ = transport.Close() })

	return testRequestUsingTransport(server, transport)
}

func testRequestUsingTransport(server *Server, transport http.RoundTripper) (*http.Response, error) {
	client := &http.Client{
		Transport: transport,
	}

	uri := fmt.Sprintf("https://localhost:%d/", server.HttpsPort())
	return client.Get(uri)
}

func TestServer_TLSCipherSuites(t *testing.T) {
	t.Run("with custom cipher suites", func(t *testing.T) {
		target := testTarget(t, func(w http.ResponseWriter, r *http.Request) {})
		
		// Create server with custom cipher suites (only non-CBC suites)
		// Note: Using ECDSA cipher suites since the test certificate is ECDSA-based
		config := &Config{
			HttpPort:  0,
			HttpsPort: 0,
			TLSCipherSuites: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		}
		router := NewRouter(t.TempDir() + "/state")
		server := NewServer(config, router)
		server.Start()
		t.Cleanup(func() { server.Stop() })

		certPath, keyPath := prepareTestCertificateFiles(t)
		serviceOptions := defaultServiceOptions
		serviceOptions.TLSEnabled = true
		serviceOptions.TLSCertificatePath = certPath
		serviceOptions.TLSPrivateKeyPath = keyPath

		testDeployTarget(t, target, server, serviceOptions)

		// Test that HTTPS works with the configured cipher suites
		// Force TLS 1.2 to test cipher suite configuration (TLS 1.3 ciphers are not configurable)
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MaxVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				},
			},
		}

		resp, err := testRequestUsingTransport(server, transport)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, uint16(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256), resp.TLS.CipherSuite)
	})

	t.Run("with invalid cipher suite configuration", func(t *testing.T) {
		config := &Config{
			HttpPort:        0,
			HttpsPort:       0,
			TLSCipherSuites: "TLS_INVALID_CIPHER_SUITE",
		}
		router := NewRouter(t.TempDir() + "/state")
		server := NewServer(config, router)
		
		err := server.Start()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown cipher suite")
	})
}
