package winrm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

func (s *WinRMSuite) TestCredSSPTSRequestRoundTrip(c *C) {
	original := tsRequest{
		Version:     credSSPDefaultVersion,
		NegoTokens:  []negoDataItem{{NegoToken: []byte("nego-1")}, {NegoToken: []byte("nego-2")}},
		AuthInfo:    []byte("auth-info"),
		PubKeyAuth:  []byte("pub-key"),
		ClientNonce: []byte("nonce"),
	}

	encoded, err := marshalTSRequest(original)
	c.Assert(err, IsNil)

	decoded, err := unmarshalTSRequest(encoded)
	c.Assert(err, IsNil)
	c.Assert(decoded.Version, Equals, original.Version)
	c.Assert(decoded.NegoTokens, DeepEquals, original.NegoTokens)
	c.Assert(decoded.AuthInfo, DeepEquals, original.AuthInfo)
	c.Assert(decoded.PubKeyAuth, DeepEquals, original.PubKeyAuth)
	c.Assert(decoded.ClientNonce, DeepEquals, original.ClientNonce)
}

func (s *WinRMSuite) TestCredSSPCredentialsRoundTrip(c *C) {
	encoded, err := marshalCredentials("DOMAIN", "administrator", "s3cr3t")
	c.Assert(err, IsNil)

	var creds tsCredentials
	rest, err := asn1.Unmarshal(encoded, &creds)
	c.Assert(err, IsNil)
	c.Assert(len(rest), Equals, 0)
	c.Assert(creds.CredType, Equals, credSSPAuthTypePassword)

	var passwordCreds tspasswordCreds
	rest, err = asn1.Unmarshal(creds.Credentials, &passwordCreds)
	c.Assert(err, IsNil)
	c.Assert(len(rest), Equals, 0)
	c.Assert(string(passwordCreds.DomainName), Equals, "DOMAIN")
	c.Assert(string(passwordCreds.UserName), Equals, "administrator")
	c.Assert(string(passwordCreds.Password), Equals, "s3cr3t")
}

func (s *WinRMSuite) TestCredSSPTrailerLengthTable(c *C) {
	encryption, err := NewEncryption("credssp")
	c.Assert(err, IsNil)

	testCases := []struct {
		name       string
		messageLen int
		cipher     string
		expected   int
	}{
		{name: "gcm", messageLen: 31, cipher: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", expected: 16},
		{name: "rc4", messageLen: 31, cipher: "TLS_RSA_WITH_RC4_128_SHA", expected: 20},
		{name: "3des", messageLen: 31, cipher: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", expected: 25},
		{name: "aes-cbc-sha256", messageLen: 31, cipher: "TLS_RSA_WITH_AES_128_CBC_SHA256", expected: 33},
		{name: "aes-cbc-sha384", messageLen: 31, cipher: "TLS_RSA_WITH_AES_256_CBC_SHA384", expected: 49},
	}

	for _, tc := range testCases {
		c.Assert(encryption.getCredSSPTrailerLength(tc.messageLen, tc.cipher), Equals, tc.expected, Commentf(tc.name))
	}
}

func (s *WinRMSuite) TestCredSSPBuildDecryptRoundTrip(c *C) {
	clientConn, serverConn, err := newCredSSPTLSHarness()
	c.Assert(err, IsNil)

	encryption, err := NewEncryption("credssp")
	c.Assert(err, IsNil)
	encryption.tlsConn = clientConn.tlsConn
	encryption.credsspConn = clientConn.memConn

	request := []byte("create shell request")
	wrappedRequest, err := encryption.buildCredSSPMessage(request, "host")
	c.Assert(err, IsNil)
	c.Assert(len(wrappedRequest) > 4, Equals, true)

	if err := serverConn.memConn.pushIncoming(wrappedRequest[4:]); err != nil {
		c.Fatal(err)
	}
	receivedRequest := make([]byte, len(request))
	n, err := serverConn.tlsConn.Read(receivedRequest)
	c.Assert(err, IsNil)
	c.Assert(receivedRequest[:n], DeepEquals, request)

	response := []byte("create shell response")
	_, err = serverConn.tlsConn.Write(response)
	c.Assert(err, IsNil)
	serverCiphertext, err := serverConn.memConn.popOutgoing(5 * time.Second)
	c.Assert(err, IsNil)
	serverCiphertext = serverConn.memConn.drainOutgoing(serverCiphertext)

	cipherName := tls.CipherSuiteName(clientConn.tlsConn.ConnectionState().CipherSuite)
	trailer := encryption.getCredSSPTrailerLength(len(response), cipherName)
	payload := make([]byte, 4+len(serverCiphertext))
	binary.LittleEndian.PutUint32(payload[:4], uint32(trailer))
	copy(payload[4:], serverCiphertext)

	decrypted, err := encryption.decryptCredsspMessage(payload, "host")
	c.Assert(err, IsNil)
	c.Assert(decrypted, DeepEquals, response)
}

func (s *WinRMSuite) TestFindCredSSPToken(c *C) {
	headers := http.Header{}
	headers.Add("WWW-Authenticate", "Negotiate")
	headers.Add("WWW-Authenticate", "CredSSP YWJjZA==")

	token, found, err := findCredSSPToken(headers)
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(string(token), Equals, "abcd")
}

func TestCredSSPMemoryConn(t *testing.T) {
	conn := newCredSSPMemoryConn()
	defer conn.Close()

	payload := []byte("hello")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	out, err := conn.popOutgoing(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.pushIncoming(out); err != nil {
		t.Fatal(err)
	}

	buffer := make([]byte, len(payload))
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "hello" {
		t.Fatalf("unexpected payload %q", string(buffer[:n]))
	}
}

type credSSPTLSEndpoint struct {
	tlsConn *tls.Conn
	memConn *credSSPMemoryConn
}

func newCredSSPTLSHarness() (*credSSPTLSEndpoint, *credSSPTLSEndpoint, error) {
	certificate, err := generateCredSSPTestCertificate()
	if err != nil {
		return nil, nil, err
	}

	clientMem := newCredSSPMemoryConn()
	serverMem := newCredSSPMemoryConn()

	clientTLS := tls.Client(clientMem, &tls.Config{
		//nolint:gosec
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	serverTLS := tls.Server(serverMem, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})

	clientErr := make(chan error, 1)
	serverErr := make(chan error, 1)
	go func() { clientErr <- clientTLS.Handshake() }()
	go func() { serverErr <- serverTLS.Handshake() }()

	if err := pumpCredSSPHandshake(clientMem, serverMem, clientErr, serverErr); err != nil {
		return nil, nil, err
	}

	return &credSSPTLSEndpoint{tlsConn: clientTLS, memConn: clientMem}, &credSSPTLSEndpoint{tlsConn: serverTLS, memConn: serverMem}, nil
}

func pumpCredSSPHandshake(clientMem, serverMem *credSSPMemoryConn, clientErr, serverErr <-chan error) error {
	clientDone := false
	serverDone := false
	timeout := time.After(10 * time.Second)

	for !clientDone || !serverDone {
		select {
		case err := <-clientErr:
			if err != nil {
				return err
			}
			clientDone = true
		case err := <-serverErr:
			if err != nil {
				return err
			}
			serverDone = true
		case outgoing := <-clientMem.outgoing:
			if err := serverMem.pushIncoming(outgoing); err != nil {
				return err
			}
		case outgoing := <-serverMem.outgoing:
			if err := clientMem.pushIncoming(outgoing); err != nil {
				return err
			}
		case <-timeout:
			return errors.New("timed out waiting for TLS handshake")
		}
	}

	return nil
}

func generateCredSSPTestCertificate() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "credssp.test",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
	}, nil
}
