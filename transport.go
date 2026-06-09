// 로컬에서 빌드시 GOPROXY, GOMODCACHE 영향을 피하기 위해 로컬 경로 명시
// GOOS=linux GOARCH=arm64 xcaddy build --with github.com/dgdsingen/caddy-transport-s3=.
//
// caddys3는 reverse_proxy 요청을 AWS SigV4로 서명하는 transport를 제공한다.
// 별도의 aws-sigv4-proxy sidecar 없이 직접 private s3 bucket에 직접 프록시할 수 있게 된다.
package caddys3

import (
	"fmt"
	"net/http"
	"strings"
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

	// TLS 위에서 서명하므로 본문을 미리 해싱하지 않고 S3가 전송 계층에서 무결성을 검증하도록 맡긴다. 모든 method에 유효하다.
	unsignedPayload = "UNSIGNED-PAYLOAD"

	amzContentSHA256Header = "X-Amz-Content-Sha256"
)

// S3는 이 헤더들을 무시하므로 서명 전에 제거해야 한다. 아니면 S3 수신값과 서명 간 불일치 에러남
var proxyHeaders = []string{
	"Via",
	"X-Forwarded-For",
	"X-Forwarded-Proto",
	"X-Forwarded-Host",
}

// S3Transport는 요청을 AWS SigV4로 서명한 뒤 내장된 HTTP transport로 위임한다.
// HTTPTransport를 embed 하므로 transport s3 블록 안에서 transport http 옵션을 그대로 쓸 수 있다.
type S3Transport struct {
	*reverseproxy.HTTPTransport

	// (Optional) bucket이 위치한 AWS region. 비어 있으면 upstream host에서 추론한다.
	// (예: bucket.s3.<region>.amazonaws.com)
	// 그러므로 host에 region이 없는 custom S3 endpoint에서만 명시해주면 된다.
	Region string `json:"region,omitempty"`

	// 서명 서비스명. 기본값은 "s3"
	Service string `json:"service,omitempty"`

	// 여러 profile이 있을 때 사용할 profile.
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

// AWS 설정 로드 (기본 자격증명 체인을 따르므로 IAM role, env, profile 모두 동작)
// SigV4 sign 생성 후 HTTP transport를 provision 한다.
func (t *S3Transport) Provision(ctx caddy.Context) error {
	if t.Service == "" {
		t.Service = defaultService
	}

	var opts []func(*config.LoadOptions) error
	if t.Region != "" {
		opts = append(opts, config.WithRegion(t.Region))
	}
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

// transport s3 블록 파싱. region, service, profile은 직접 소비하고
// 그 외 sub directive는 내장 HTTPTransport로 위임함
func (t *S3Transport) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if t.HTTPTransport == nil {
		t.HTTPTransport = new(reverseproxy.HTTPTransport)
	}

	d.Next() // transport 이름("s3") 소비
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
			// S3Transport의 키가 아니면 해당 디렉티브 전체(인자와 중첩 블록 포함)를 내장 HTTPTransport로 넘김
			forwarded = append(forwarded, d.NextSegment()...)
		}
	}

	if len(forwarded) == 0 {
		return nil
	}

	// 내장 HTTPTransport.UnmarshalCaddyfile은 이름 토큰을 소비한 뒤 블록을 읽으므로 "s3 { <forwarded> }" 형태로 재조립한다.
	// 닫는 중괄호는 마지막 forwarded 토큰보다 뒷줄에 둬야 Caddyfile이 같은 줄 인자로 오인하지 않는다.
	brace := func(text string, line int) caddyfile.Token {
		return caddyfile.Token{File: nameTok.File, Line: line, Text: text}
	}
	lastLine := forwarded[len(forwarded)-1].Line
	tokens := append([]caddyfile.Token{nameTok, brace("{", nameTok.Line)}, forwarded...)
	tokens = append(tokens, brace("}", lastLine+1))

	return t.HTTPTransport.UnmarshalCaddyfile(caddyfile.NewDispenser(tokens))
}

// RoundTrip은 요청을 SigV4로 서명한 뒤 내장 HTTP transport로 위임한다.
// 서명을 위임보다 먼저 수행하므로 자격증명 획득에 실패하면 서명되지 않은 요청을 보내는 대신 중단된다.
func (t *S3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.sign(req); err != nil {
		return nil, err
	}
	return t.HTTPTransport.RoundTrip(req)
}

func (t *S3Transport) sign(req *http.Request) error {
	return t.signAt(req, time.Now())
}

// signAt은 req에 SigV4 헤더를 계산해 주입한다.
// 자격증명은 매번 provider에서 새로 가져오므로 SDK가 관리하는 갱신(IAM role, STS)이 반영된다.
func (t *S3Transport) signAt(req *http.Request, signingTime time.Time) error {
	creds, err := t.creds.Retrieve(req.Context())
	if err != nil {
		return err
	}

	// client host 대신 upstream host로 변경 (s3가 수신하는 host와 서명값을 맞춤)
	req.Host = req.URL.Host
	for _, h := range proxyHeaders {
		req.Header.Del(h)
	}
	req.Header.Set(amzContentSHA256Header, unsignedPayload)

	// 명시된 region이 우선이고, 없으면 upstream host에서 추론한다.
	region := t.Region
	if region == "" {
		region = regionFromHost(req.URL.Host)
	}
	if region == "" {
		return fmt.Errorf("s3 transport: region이 설정되지 않았고 upstream host %q에서 추론할 수 없습니다", req.URL.Host)
	}

	return t.signer.SignHTTP(req.Context(), creds, req, unsignedPayload, t.Service, region, signingTime)
}

// regionFromHost는 표준 S3 엔드포인트 host에서 AWS 리전을 추출한다
// (예: "<bucket>.s3.<region>.amazonaws.com" 또는 "s3.<region>.amazonaws.com")
// 레거시 글로벌 형태 "...s3.amazonaws.com"은 us-east-1로 매핑한다.
// AWS가 아닌 host(custom endpoint)에는 ""를 반환하며, 이 경우 region을 명시해야 한다.
func regionFromHost(host string) string {
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i] // 포트 제거
	}
	if !strings.HasSuffix(host, ".amazonaws.com") {
		return ""
	}

	labels := strings.Split(host, ".")
	for i, l := range labels {
		if l == "s3" {
			if labels[i+1] == "amazonaws" {
				return "us-east-1"
			}
			return labels[i+1]
		}
	}
	return ""
}
