package winrm

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bodgit/ntlmssp"
	"github.com/masterzen/winrm/soap"
)

const (
	credSSPHeaderName = "CredSSP"
)

var (
	errCredSSPClosed = errors.New("credssp connection is closed")
)

type credSSPMemoryConn struct {
	readMu   sync.Mutex
	readBuf  bytes.Buffer
	incoming chan []byte
	outgoing chan []byte
	closeCh  chan struct{}
}

func newCredSSPMemoryConn() *credSSPMemoryConn {
	return &credSSPMemoryConn{
		incoming: make(chan []byte, 32),
		outgoing: make(chan []byte, 32),
		closeCh:  make(chan struct{}),
	}
}

func (c *credSSPMemoryConn) Read(p []byte) (int, error) {
	for {
		c.readMu.Lock()
		if c.readBuf.Len() > 0 {
			n, _ := c.readBuf.Read(p)
			c.readMu.Unlock()
			return n, nil
		}
		c.readMu.Unlock()

		select {
		case data, ok := <-c.incoming:
			if !ok {
				return 0, io.EOF
			}
			c.readMu.Lock()
			c.readBuf.Write(data)
			c.readMu.Unlock()
		case <-c.closeCh:
			return 0, io.EOF
		}
	}
}

func (c *credSSPMemoryConn) Write(p []byte) (int, error) {
	payload := append([]byte(nil), p...)
	select {
	case c.outgoing <- payload:
		return len(p), nil
	case <-c.closeCh:
		return 0, errCredSSPClosed
	}
}

func (c *credSSPMemoryConn) Close() error {
	select {
	case <-c.closeCh:
	default:
		close(c.closeCh)
		close(c.incoming)
	}
	return nil
}

func (c *credSSPMemoryConn) LocalAddr() net.Addr {
	return dummyAddr("local")
}

func (c *credSSPMemoryConn) RemoteAddr() net.Addr {
	return dummyAddr("remote")
}

func (c *credSSPMemoryConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *credSSPMemoryConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *credSSPMemoryConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func (c *credSSPMemoryConn) pushIncoming(payload []byte) error {
	data := append([]byte(nil), payload...)
	select {
	case c.incoming <- data:
		return nil
	case <-c.closeCh:
		return errCredSSPClosed
	}
}

func (c *credSSPMemoryConn) popOutgoing(timeout time.Duration) ([]byte, error) {
	select {
	case payload := <-c.outgoing:
		return payload, nil
	case <-time.After(timeout):
		return nil, errors.New("timed out waiting for outgoing TLS records")
	case <-c.closeCh:
		return nil, io.EOF
	}
}

func (c *credSSPMemoryConn) drainOutgoing(first []byte) []byte {
	payload := append([]byte(nil), first...)
	for {
		select {
		case extra := <-c.outgoing:
			payload = append(payload, extra...)
		default:
			return payload
		}
	}
}

type dummyAddr string

func (d dummyAddr) Network() string {
	return "credssp"
}

func (d dummyAddr) String() string {
	return string(d)
}

// ClientCredSSP provides a transport via CredSSP.
type ClientCredSSP struct {
	clientRequest

	httpClient *http.Client
	endpoint   *Endpoint
	memConn    *credSSPMemoryConn
	tlsConn    *tls.Conn
	ntlmClient *ntlmssp.Client
	encryption *Encryption

	handshakeComplete bool
	mu                sync.Mutex
}

// NewClientCredSSPWithDial creates a CredSSP client with custom dialer.
func NewClientCredSSPWithDial(dial func(network, addr string) (net.Conn, error)) *ClientCredSSP {
	return &ClientCredSSP{
		clientRequest: clientRequest{
			dial: dial,
		},
	}
}

// NewClientCredSSPWithProxyFunc creates a CredSSP client with custom proxy.
func NewClientCredSSPWithProxyFunc(proxyfunc func(req *http.Request) (*url.URL, error)) *ClientCredSSP {
	return &ClientCredSSP{
		clientRequest: clientRequest{
			proxyfunc: proxyfunc,
		},
	}
}

// NewClientCredSSP creates a CredSSP client.
func NewClientCredSSP() *ClientCredSSP {
	return &ClientCredSSP{}
}

// Transport creates the wrapped CredSSP transport.
func (c *ClientCredSSP) Transport(endpoint *Endpoint) error {
	if err := c.clientRequest.Transport(endpoint); err != nil {
		return err
	}
	c.endpoint = endpoint
	c.httpClient = &http.Client{Transport: c.clientRequest.transport}
	return nil
}

// Post makes post to the winrm soap service over CredSSP.
func (c *ClientCredSSP) Post(client *Client, request *soap.SoapMessage) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureHandshake(client); err != nil {
		return "", err
	}

	if c.encryption == nil {
		encryption, err := NewEncryption("credssp")
		if err != nil {
			return "", err
		}
		encryption.httpClient = c.httpClient
		encryption.tlsConn = c.tlsConn
		encryption.credsspConn = c.memConn
		encryption.ntlmClient = c.ntlmClient
		c.encryption = encryption
	}

	return c.encryption.PrepareEncryptedRequest(client, client.url, []byte(request.String()))
}

func (c *ClientCredSSP) ensureHandshake(client *Client) error {
	if c.handshakeComplete {
		return nil
	}

	memConn := newCredSSPMemoryConn()
	tlsConn := tls.Client(memConn, c.tlsConfig())

	handshakeErr := make(chan error, 1)
	go func() {
		handshakeErr <- tlsConn.Handshake()
	}()

	for {
		select {
		case err := <-handshakeErr:
			if err != nil {
				_ = memConn.Close()
				return fmt.Errorf("credssp tls handshake failed: %w", err)
			}

			c.memConn = memConn
			c.tlsConn = tlsConn
			if err := c.performCredSSPAuth(client); err != nil {
				_ = memConn.Close()
				return err
			}
			c.handshakeComplete = true
			return nil
		case out := <-memConn.outgoing:
			token, err := c.exchangeCredSSPToken(client.url, out)
			if err != nil {
				_ = memConn.Close()
				return err
			}
			if len(token) > 0 {
				if err := memConn.pushIncoming(token); err != nil {
					return err
				}
			}
		}
	}
}

func (c *ClientCredSSP) tlsConfig() *tls.Config {
	cfg := &tls.Config{
		//nolint:gosec
		InsecureSkipVerify: c.endpoint.Insecure || len(c.endpoint.CACert) == 0,
		ServerName:         c.endpoint.TLSServerName,
		MinVersion:         tls.VersionTLS12,
	}

	if len(c.endpoint.CACert) > 0 {
		if certPool, err := readCACerts(c.endpoint.CACert); err == nil {
			cfg.RootCAs = certPool
			cfg.InsecureSkipVerify = c.endpoint.Insecure
		}
	}
	return cfg
}

func (c *ClientCredSSP) performCredSSPAuth(client *Client) error {
	user, domain := splitUsername(client.username)
	ntlmClient, err := ntlmssp.NewClient(
		ntlmssp.SetUserInfo(user, client.password),
		ntlmssp.SetDomain(domain),
		ntlmssp.SetVersion(ntlmssp.DefaultVersion()),
	)
	if err != nil {
		return err
	}

	version := credSSPDefaultVersion

	negoToken, err := ntlmClient.Authenticate(nil, nil)
	if err != nil {
		return err
	}
	challengeRequest := tsRequest{
		Version:    version,
		NegoTokens: []negoDataItem{{NegoToken: negoToken}},
	}

	challengeResponse, err := c.sendTSRequest(client.url, challengeRequest)
	if err != nil {
		return err
	}
	if challengeResponse == nil || len(challengeResponse.NegoTokens) == 0 {
		return errors.New("credssp challenge response missing NTLM challenge")
	}

	if challengeResponse.Version >= credSSPMinimumVersion && challengeResponse.Version < version {
		version = challengeResponse.Version
	}

	authToken, err := ntlmClient.Authenticate(challengeResponse.NegoTokens[0].NegoToken, nil)
	if err != nil {
		return err
	}

	_, err = c.sendTSRequest(client.url, tsRequest{
		Version:    version,
		NegoTokens: []negoDataItem{{NegoToken: authToken}},
	})
	if err != nil {
		return err
	}

	securitySession := ntlmClient.SecuritySession()
	if securitySession == nil {
		return errors.New("credssp ntlm security session not established")
	}

	if len(c.tlsConn.ConnectionState().PeerCertificates) == 0 {
		return errors.New("credssp tls peer certificate missing")
	}
	serverPublicKey := c.tlsConn.ConnectionState().PeerCertificates[0].RawSubjectPublicKeyInfo

	nonce := []byte(nil)
	if version >= credSSPVersion5 {
		nonce = make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
	}

	clientPubKeyAuth, expectedServerPubKeyAuth, err := buildPubKeyAuthData(securitySession, serverPublicKey, version, nonce)
	if err != nil {
		return err
	}

	pubKeyResponse, err := c.sendTSRequest(client.url, tsRequest{
		Version:     version,
		PubKeyAuth:  clientPubKeyAuth,
		ClientNonce: nonce,
	})
	if err != nil {
		return err
	}
	if pubKeyResponse == nil || len(pubKeyResponse.PubKeyAuth) == 0 {
		return errors.New("credssp pubKeyAuth response missing")
	}

	serverPubKeyAuth, err := unwrapCredSSPData(securitySession, pubKeyResponse.PubKeyAuth)
	if err != nil {
		return err
	}
	if !bytes.Equal(serverPubKeyAuth, expectedServerPubKeyAuth) {
		return errors.New("credssp pubKeyAuth verification failed")
	}

	credentials, err := marshalCredentials(domain, user, client.password)
	if err != nil {
		return err
	}
	wrappedCredentials, err := wrapCredSSPData(securitySession, credentials)
	if err != nil {
		return err
	}

	_, err = c.sendTSRequest(client.url, tsRequest{
		Version:     version,
		AuthInfo:    wrappedCredentials,
		ClientNonce: nonce,
	})
	if err != nil {
		return err
	}

	c.ntlmClient = ntlmClient
	return nil
}

func buildPubKeyAuthData(session *ntlmssp.SecuritySession, serverPublicKey []byte, version int, nonce []byte) ([]byte, []byte, error) {
	if version >= credSSPVersion5 {
		clientHash := credSSPBindingHash("CredSSP Client-To-Server Binding Hash\x00", nonce, serverPublicKey)
		serverHash := credSSPBindingHash("CredSSP Server-To-Client Binding Hash\x00", nonce, serverPublicKey)
		wrapped, err := wrapCredSSPData(session, clientHash)
		if err != nil {
			return nil, nil, err
		}
		return wrapped, serverHash, nil
	}

	pubKeyPlusOne := append([]byte(nil), serverPublicKey...)
	pubKeyPlusOne[0]++
	wrapped, err := wrapCredSSPData(session, pubKeyPlusOne)
	if err != nil {
		return nil, nil, err
	}
	return wrapped, serverPublicKey, nil
}

func credSSPBindingHash(prefix string, nonce, publicKey []byte) []byte {
	hash := sha256.Sum256(bytes.Join([][]byte{
		[]byte(prefix),
		nonce,
		publicKey,
	}, nil))
	return hash[:]
}

func wrapCredSSPData(session *ntlmssp.SecuritySession, payload []byte) ([]byte, error) {
	sealed, signature, err := session.Wrap(payload)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 4+len(signature)+len(sealed))
	binary.LittleEndian.PutUint32(data[:4], uint32(len(signature)))
	copy(data[4:], signature)
	copy(data[4+len(signature):], sealed)

	return data, nil
}

func unwrapCredSSPData(session *ntlmssp.SecuritySession, payload []byte) ([]byte, error) {
	if len(payload) < 4 {
		return nil, errors.New("invalid credssp payload")
	}
	signatureLength := int(binary.LittleEndian.Uint32(payload[:4]))
	if len(payload) < 4+signatureLength {
		return nil, errors.New("invalid credssp signature length")
	}

	signature := payload[4 : 4+signatureLength]
	sealed := payload[4+signatureLength:]
	return session.Unwrap(sealed, signature)
}

func (c *ClientCredSSP) sendTSRequest(endpoint string, request tsRequest) (*tsRequest, error) {
	payload, err := marshalTSRequest(request)
	if err != nil {
		return nil, err
	}

	if _, err := c.tlsConn.Write(payload); err != nil {
		return nil, err
	}

	outgoing, err := c.memConn.popOutgoing(c.endpoint.Timeout)
	if err != nil {
		return nil, err
	}

	responseToken, err := c.exchangeCredSSPToken(endpoint, c.memConn.drainOutgoing(outgoing))
	if err != nil {
		return nil, err
	}
	if len(responseToken) > 0 {
		if err := c.memConn.pushIncoming(responseToken); err != nil {
			return nil, err
		}
	}

	return readTSRequest(c.tlsConn, c.endpoint.Timeout)
}

func readTSRequest(conn net.Conn, timeout time.Duration) (*tsRequest, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	defer conn.SetReadDeadline(time.Time{})

	buffer := make([]byte, 0, 8192)
	chunk := make([]byte, 4096)
	for {
		n, err := conn.Read(chunk)
		if n > 0 {
			buffer = append(buffer, chunk[:n]...)
			request, asnErr := unmarshalTSRequest(buffer)
			if asnErr == nil {
				return request, nil
			}
			if !isASN1TruncatedError(asnErr) {
				return nil, asnErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, io.EOF
			}
			return nil, err
		}
	}
}

func isASN1TruncatedError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "truncated") || strings.Contains(err.Error(), "data truncated")
}

func (c *ClientCredSSP) exchangeCredSSPToken(endpoint string, token []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", endpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "WinRM client")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", credSSPHeaderName, base64.StdEncoding.EncodeToString(token)))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return nil, err
	}

	responseToken, found, err := findCredSSPToken(resp.Header)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("credssp server did not return %s token", credSSPHeaderName)
	}
	return responseToken, nil
}

func findCredSSPToken(headers http.Header) ([]byte, bool, error) {
	for _, value := range headers.Values("WWW-Authenticate") {
		if value == credSSPHeaderName {
			return nil, true, nil
		}
		prefix := credSSPHeaderName + " "
		if strings.HasPrefix(value, prefix) {
			payload := strings.TrimSpace(strings.TrimPrefix(value, prefix))
			token, err := base64.StdEncoding.DecodeString(payload)
			return token, true, err
		}
	}
	return nil, false, nil
}
