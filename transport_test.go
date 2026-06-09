package caddys3

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

// newTestTransport builds an S3Transport with static credentials and a signer,
// bypassing Provision so signing can be tested in isolation.
func newTestTransport(token string) *S3Transport {
	return &S3Transport{
		Region:  "ap-northeast-2",
		Service: "s3",
		creds:   credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "SECRETKEY", token),
		signer:  v4.NewSigner(),
	}
}

func TestSignAddsSigV4Headers(t *testing.T) {
	tr := newTestTransport("")
	req, err := http.NewRequest(http.MethodGet, "https://bucket.s3.ap-northeast-2.amazonaws.com/foo.js", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	if err := tr.sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}

	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") {
		t.Errorf("Authorization = %q, want AWS4-HMAC-SHA256 prefix with our access key", auth)
	}
	if !strings.Contains(auth, "/ap-northeast-2/s3/aws4_request") {
		t.Errorf("Authorization scope missing region/service: %q", auth)
	}
	if req.Header.Get("X-Amz-Date") == "" {
		t.Error("X-Amz-Date header not set")
	}
	if req.Header.Get("X-Amz-Content-Sha256") == "" {
		t.Error("X-Amz-Content-Sha256 header not set")
	}
}

// signedHeaders extracts the SignedHeaders list from an Authorization header.
func signedHeaders(auth string) []string {
	_, rest, ok := strings.Cut(auth, "SignedHeaders=")
	if !ok {
		return nil
	}
	list, _, _ := strings.Cut(rest, ",")
	return strings.Split(list, ";")
}

// TestSignExcludesProxyHeaders guards against the SignatureDoesNotMatch we hit
// in practice: Caddy adds Via / X-Forwarded-* headers whose values change
// across hops. They must be stripped before signing (and dropped from the
// request) so the signed host/headers match what S3 receives.
func TestSignExcludesProxyHeaders(t *testing.T) {
	proxyHdrs := []string{"Via", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host"}

	tr := newTestTransport("")
	req, _ := http.NewRequest(http.MethodGet, "https://bucket.s3.ap-northeast-2.amazonaws.com/index.html", nil)
	req.Header.Set("Via", "1.1 Caddy")
	req.Header.Set("X-Forwarded-For", "::1")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-Host", "example.com")

	if err := tr.sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}

	signed := signedHeaders(req.Header.Get("Authorization"))
	for _, sh := range signed {
		for _, ph := range proxyHdrs {
			if strings.EqualFold(sh, ph) {
				t.Errorf("SignedHeaders must not include proxy header %q; got %v", ph, signed)
			}
		}
	}

	for _, ph := range proxyHdrs {
		if v := req.Header.Get(ph); v != "" {
			t.Errorf("proxy header %q should be removed from the request, got %q", ph, v)
		}
	}
}

// Without a session token, the security-token header must be absent.
func TestSignOmitsSecurityTokenWhenStatic(t *testing.T) {
	tr := newTestTransport("")
	req, _ := http.NewRequest(http.MethodGet, "https://bucket.s3.ap-northeast-2.amazonaws.com/foo.js", nil)
	if err := tr.sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != "" {
		t.Errorf("X-Amz-Security-Token = %q, want empty for static creds", got)
	}
}

// Temporary credentials (IAM role / STS) carry a session token that must be
// forwarded as X-Amz-Security-Token.
func TestSignForwardsSessionToken(t *testing.T) {
	tr := newTestTransport("SESSIONTOKEN123")
	req, _ := http.NewRequest(http.MethodGet, "https://bucket.s3.ap-northeast-2.amazonaws.com/foo.js", nil)
	if err := tr.sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != "SESSIONTOKEN123" {
		t.Errorf("X-Amz-Security-Token = %q, want SESSIONTOKEN123", got)
	}
}

// TestRoundTripDelegatesSignedRequest verifies the full path: RoundTrip signs
// the request and the embedded HTTPTransport actually delivers it upstream.
func TestRoundTripDelegatesSignedRequest(t *testing.T) {
	var gotAuth, gotSHA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotSHA = r.Header.Get(amzContentSHA256Header)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	tr := newTestTransport("")
	tr.HTTPTransport = &reverseproxy.HTTPTransport{}
	if err := tr.HTTPTransport.Provision(ctx); err != nil {
		t.Fatalf("provision HTTPTransport: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/foo.js", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	resp.Body.Close()

	if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256") {
		t.Errorf("upstream Authorization = %q, want signed request", gotAuth)
	}
	if gotSHA == "" {
		t.Error("upstream did not receive X-Amz-Content-Sha256")
	}
}

type errCredsProvider struct{}

func (errCredsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, errors.New("no credentials available")
}

// TestRoundTripReturnsSignError ensures a credential failure aborts before
// delegating (the embedded transport is nil here, so any delegation panics).
func TestRoundTripReturnsSignError(t *testing.T) {
	tr := &S3Transport{
		Region:  "ap-northeast-2",
		Service: "s3",
		creds:   errCredsProvider{},
		signer:  v4.NewSigner(),
	}

	req, _ := http.NewRequest(http.MethodGet, "https://bucket.s3.ap-northeast-2.amazonaws.com/foo.js", nil)
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("expected error from failed credential retrieval, got nil")
	}
}

func TestCaddyModuleID(t *testing.T) {
	got := S3Transport{}.CaddyModule().ID
	want := caddy.ModuleID("http.reverse_proxy.transport.s3")
	if got != want {
		t.Errorf("module ID = %q, want %q", got, want)
	}
}

func TestProvisionDefaultsAndProvider(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	tr := &S3Transport{Region: "ap-northeast-2"}
	if err := tr.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	if tr.Service != defaultService {
		t.Errorf("Service = %q, want default %q", tr.Service, defaultService)
	}
	if tr.signer == nil {
		t.Error("signer not initialized")
	}
	if tr.creds == nil {
		t.Error("credentials provider not initialized")
	}
	if tr.HTTPTransport == nil {
		t.Error("embedded HTTPTransport not initialized")
	}
}

// Region is optional now (derived from the upstream host at sign time), so
// Provision must succeed without it.
func TestProvisionWithoutRegionSucceeds(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	tr := &S3Transport{} // no region
	if err := tr.Provision(ctx); err != nil {
		t.Fatalf("Provision without region should succeed: %v", err)
	}
}

// TestUnmarshalCaddyfilePlain verifies the flat syntax: our keys are consumed
// directly while http transport options are forwarded to the embedded
// HTTPTransport.
func TestUnmarshalCaddyfilePlain(t *testing.T) {
	d := caddyfile.NewTestDispenser(`s3 {
		region ap-northeast-2
		profile myprofile
		dial_timeout 5s
		versions h2 h1
	}`)

	var tr S3Transport
	if err := tr.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}

	if tr.Region != "ap-northeast-2" {
		t.Errorf("Region = %q, want ap-northeast-2", tr.Region)
	}
	if tr.Profile != "myprofile" {
		t.Errorf("Profile = %q, want myprofile", tr.Profile)
	}
	if tr.HTTPTransport == nil {
		t.Fatal("embedded HTTPTransport is nil")
	}
	if tr.HTTPTransport.DialTimeout != caddy.Duration(5*time.Second) {
		t.Errorf("DialTimeout = %v, want 5s", time.Duration(tr.HTTPTransport.DialTimeout))
	}
	if len(tr.HTTPTransport.Versions) != 2 {
		t.Errorf("Versions = %v, want [h2 h1]", tr.HTTPTransport.Versions)
	}
}

// TestUnmarshalCaddyfileOnlyOurKeys covers a block with no http options: the
// embedded transport must be left provisionable (non-nil) without error.
func TestUnmarshalCaddyfileOnlyOurKeys(t *testing.T) {
	d := caddyfile.NewTestDispenser(`s3 {
		region us-east-1
	}`)

	var tr S3Transport
	if err := tr.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if tr.Region != "us-east-1" {
		t.Errorf("Region = %q, want us-east-1", tr.Region)
	}
}

// TestSignOverridesHostWithUpstream ensures the signed host matches the S3
// upstream even when reverse_proxy leaves the original client Host header in
// place — otherwise SigV4 signs the wrong host and S3 returns 403.
func TestSignOverridesHostWithUpstream(t *testing.T) {
	const upstream = "bucket.s3.ap-northeast-2.amazonaws.com"

	tr := newTestTransport("")
	req, _ := http.NewRequest(http.MethodGet, "https://"+upstream+"/foo.js", nil)
	req.Host = "example.com" // simulate the client-facing Host left by reverse_proxy

	if err := tr.sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if req.Host != upstream {
		t.Errorf("req.Host = %q, want upstream %q", req.Host, upstream)
	}

	// Re-sign a clean request (Host derived from URL) and confirm the
	// Authorization matches, proving the override fed the upstream host into
	// the signature rather than example.com.
	clean := newTestTransport("")
	cleanReq, _ := http.NewRequest(http.MethodGet, "https://"+upstream+"/foo.js", nil)
	if err := clean.signAt(cleanReq, fixedTime); err != nil {
		t.Fatalf("sign clean: %v", err)
	}
	tr2 := newTestTransport("")
	dirtyReq, _ := http.NewRequest(http.MethodGet, "https://"+upstream+"/foo.js", nil)
	dirtyReq.Host = "example.com"
	if err := tr2.signAt(dirtyReq, fixedTime); err != nil {
		t.Fatalf("sign dirty: %v", err)
	}
	if a, b := cleanReq.Header.Get("Authorization"), dirtyReq.Header.Get("Authorization"); a != b {
		t.Errorf("signatures differ — host override not applied\n clean: %s\n dirty: %s", a, b)
	}
}

var fixedTime = time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)

func TestRegionFromHost(t *testing.T) {
	cases := []struct{ host, want string }{
		{"bucket.s3.ap-northeast-2.amazonaws.com", "ap-northeast-2"},
		{"bucket.s3.ap-northeast-2.amazonaws.com:443", "ap-northeast-2"},
		{"bucket.s3.us-east-1.amazonaws.com", "us-east-1"},
		{"bucket.s3.amazonaws.com", "us-east-1"},    // legacy global endpoint
		{"s3.eu-west-1.amazonaws.com", "eu-west-1"}, // path-style
		{"minio.internal:9000", ""},                 // custom endpoint, not derivable
		{"example.com", ""},
	}
	for _, c := range cases {
		if got := regionFromHost(c.host); got != c.want {
			t.Errorf("regionFromHost(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}

// TestSignDerivesRegionFromHost: with no explicit Region, the signing region
// comes from the upstream host.
func TestSignDerivesRegionFromHost(t *testing.T) {
	tr := &S3Transport{
		Service: "s3",
		creds:   credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "SECRETKEY", ""),
		signer:  v4.NewSigner(),
	}
	req, _ := http.NewRequest(http.MethodGet, "https://bucket.s3.eu-west-1.amazonaws.com/foo.js", nil)
	if err := tr.sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if auth := req.Header.Get("Authorization"); !strings.Contains(auth, "/eu-west-1/s3/aws4_request") {
		t.Errorf("signing scope should use region derived from host: %q", auth)
	}
}

// TestSignErrorsWhenRegionUnknown: a custom endpoint with no explicit region
// must fail clearly rather than sign with an empty region.
func TestSignErrorsWhenRegionUnknown(t *testing.T) {
	tr := &S3Transport{
		Service: "s3",
		creds:   credentials.NewStaticCredentialsProvider("A", "S", ""),
		signer:  v4.NewSigner(),
	}
	req, _ := http.NewRequest(http.MethodGet, "https://minio.internal:9000/foo.js", nil)
	if err := tr.sign(req); err == nil {
		t.Fatal("expected error when region cannot be derived from host")
	}
}

var _ aws.CredentialsProvider = credentials.NewStaticCredentialsProvider("", "", "")
var _ caddyfile.Unmarshaler = (*S3Transport)(nil)
