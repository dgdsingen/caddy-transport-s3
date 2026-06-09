package caddys3

import (
	"errors"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

func init() {
	caddy.RegisterModule(S3Transport{})
}

var (
	_ caddy.Module          = (*S3Transport)(nil)
	_ caddy.Provisioner     = (*S3Transport)(nil)
	_ http.RoundTripper     = (*S3Transport)(nil)
	_ caddyfile.Unmarshaler = (*S3Transport)(nil)
)

const (
	defaultService = "s3"

	// Signing over TLS, we let S3 verify integrity at the transport layer
	// instead of pre-hashing the (often streamed) body. Valid for every method.
	unsignedPayload = "UNSIGNED-PAYLOAD"

	amzContentSHA256Header = "X-Amz-Content-Sha256"
)

type S3Transport struct {
	*reverseproxy.HTTPTransport

	// The AWS region the bucket is hosted in.
	Region string `json:"region,omitempty"`

	// The signing service name. Defaults to "s3".
	Service string `json:"service,omitempty"`

	// The AWS profile to use if multiple profiles are specified.
	Profile string `json:"profile,omitempty"`

	creds  aws.CredentialsProvider
	signer *v4.Signer
}

func (S3Transport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.transport.s3",
		New: func() caddy.Module { return new(S3Transport) },
	}
}

func (t *S3Transport) Provision(ctx caddy.Context) error {
	if t.Region == "" {
		return errors.New("region must be set")
	}
	if t.Service == "" {
		t.Service = defaultService
	}

	opts := []func(*config.LoadOptions) error{config.WithRegion(t.Region)}
	if t.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(t.Profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx.Context, opts...)
	if err != nil {
		return err
	}
	t.creds = cfg.Credentials
	t.signer = v4.NewSigner()

	if t.HTTPTransport == nil {
		t.HTTPTransport = new(reverseproxy.HTTPTransport)
	}
	return t.HTTPTransport.Provision(ctx)
}

func (t *S3Transport) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if t.HTTPTransport == nil {
		t.HTTPTransport = new(reverseproxy.HTTPTransport)
	}

	d.Next() // consume transport name ("s3")
	nameTok := d.Token()

	var forwarded []caddyfile.Token
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "region":
			if !d.NextArg() {
				return d.ArgErr()
			}
			t.Region = d.Val()
		case "service":
			if !d.NextArg() {
				return d.ArgErr()
			}
			t.Service = d.Val()
		case "profile":
			if !d.NextArg() {
				return d.ArgErr()
			}
			t.Profile = d.Val()
		default:
			// Not ours - hand the whole directive (args and any nested block) to the embedded transport
			forwarded = append(forwarded, d.NextSegment()...)
		}
	}

	if len(forwarded) == 0 {
		return nil
	}

	brace := func(text string, line int) caddyfile.Token {
		return caddyfile.Token{File: nameTok.File, Line: line, Text: text}
	}
	lastLine := forwarded[len(forwarded)-1].Line
	tokens := append([]caddyfile.Token{nameTok, brace("{", nameTok.Line)}, forwarded...)
	tokens = append(tokens, brace("}", lastLine+1))

	return t.HTTPTransport.UnmarshalCaddyfile(caddyfile.NewDispenser(tokens))
}

func (t *S3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.sign(req); err != nil {
		return nil, err
	}
	return t.HTTPTransport.RoundTrip(req)
}

func (t *S3Transport) sign(req *http.Request) error {
	creds, err := t.creds.Retrieve(req.Context())
	if err != nil {
		return err
	}

	req.Header.Set(amzContentSHA256Header, unsignedPayload)

	return t.signer.SignHTTP(req.Context(), creds, req, unsignedPayload, t.Service, t.Region, time.Now())
}
