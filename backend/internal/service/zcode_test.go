package service

import (
	"testing"
)

// TestZCodeBuildHeaders_OAuth 验证 JWT(oauth) 模式：走上游端点，Bearer 鉴权，带验证码头。
func TestZCodeBuildHeaders_OAuth(t *testing.T) {
	url, headers := ZCodeBuildHeaders("oauth", "jwt-secret-token", "captcha-verify-param", nil)

	if url != ZCodeUpstreamURL() {
		t.Fatalf("oauth 模式应走上游端点, got %s", url)
	}
	if headers["Authorization"] != "Bearer jwt-secret-token" {
		t.Fatalf("oauth 模式应使用 Bearer 鉴权, got %q", headers["Authorization"])
	}
	if headers["X-Aliyun-Captcha-Verify-Param"] != "captcha-verify-param" {
		t.Fatalf("oauth 模式应带验证码参数, got %q", headers["X-Aliyun-Captcha-Verify-Param"])
	}
	// ZCode 专有头部
	for _, k := range []string{"X-ZCode-App-Version", "X-ZCode-Agent", "HTTP-Referer", "anthropic-version"} {
		if headers[k] == "" {
			t.Fatalf("缺少必要头部 %s", k)
		}
	}
}

// TestZCodeBuildHeaders_APIKey 验证 API Key 模式：走回退端点，x-api-key 鉴权，无验证码头。
func TestZCodeBuildHeaders_APIKey(t *testing.T) {
	url, headers := ZCodeBuildHeaders("apikey", "sk-xxxxx.secret", "", nil)

	if url != ZCodeFallbackURL() {
		t.Fatalf("apikey 模式应走回退端点, got %s", url)
	}
	if headers["x-api-key"] != "sk-xxxxx.secret" {
		t.Fatalf("apikey 模式应使用 x-api-key, got %q", headers["x-api-key"])
	}
	if _, has := headers["X-Aliyun-Captcha-Verify-Param"]; has {
		t.Fatal("apikey 模式不应带验证码参数")
	}
}

// TestZCodeBuildHeaders_DropHeaders 验证受控头部被剔除，且 x-zcode-* 前缀被剔除。
func TestZCodeBuildHeaders_DropHeaders(t *testing.T) {
	// 用逐行赋值，避免 map 字面量对齐被 gofmt 改动。
	incoming := map[string]string{}
	incoming["Host"] = "example.com"
	incoming["Authorization"] = "Bearer should-be-dropped"
	incoming["Content-Length"] = "123"
	incoming["X-Custom"] = "keep-me"
	incoming["X-ZCode-Foo"] = "should-be-dropped"
	_, headers := ZCodeBuildHeaders("apikey", "key", "", incoming)

	if headers["Authorization"] == "Bearer should-be-dropped" {
		t.Fatal("客户端 Authorization 应被剔除")
	}
	if _, has := headers["Host"]; has {
		t.Fatal("Host 应被剔除")
	}
	if headers["X-Custom"] != "keep-me" {
		t.Fatalf("普通客户端头部应透传, got %q", headers["X-Custom"])
	}
	if _, has := headers["X-ZCode-Foo"]; has {
		t.Fatal("x-zcode-* 前缀头部应被剔除")
	}
}

// TestZCodeUpstreamURLOverride 验证环境变量覆盖上游端点。
func TestZCodeUpstreamURLOverride(t *testing.T) {
	t.Setenv("ZCODE_UPSTREAM_URL", "https://custom.example.com/messages")

	if got := ZCodeUpstreamURL(); got != "https://custom.example.com/messages" {
		t.Fatalf("环境变量覆盖失败, got %s", got)
	}
}

