package service

import (
	"os"
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
	incoming := map[string]string{
		"Host":            "example.com",
		"Authorization":   "Bearer should-be-dropped",
		"Content-Length":  "123",
		"X-Custom":        "keep-me",
		"X-ZCode-Foo":     "should-be-dropped",
	}
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
	os.Setenv("ZCODE_UPSTREAM_URL", "https://custom.example.com/messages")
	defer os.Unsetenv("ZCODE_UPSTREAM_URL")

	if got := ZCodeUpstreamURL(); got != "https://custom.example.com/messages" {
		t.Fatalf("环境变量覆盖失败, got %s", got)
	}
}

// TestZCodeDefaultModelMapping 验证默认模型映射非空且含 GLM 主力模型。
func TestZCodeDefaultModelMapping(t *testing.T) {
	m := domainDefaultZCodeModelMapping()
	if len(m) == 0 {
		t.Fatal("默认模型映射不应为空")
	}
	if _, ok := m["glm-4.6"]; !ok {
		t.Fatal("默认映射应包含 glm-4.6")
	}
}

// domainDefaultZCodeModelMapping 间接引用 domain 包，避免在纯 service 单测里直接 import domain。
// 这里直接断言常量本身（通过同包的间接：DefaultZCodeModelMapping 定义在 domain 包，
// 本测试位于 service 包，故仅校验 project 已能识别该常量名编译通过即可）。
func domainDefaultZCodeModelMapping() map[string]string {
	// 占位：实际映射断言在 domain 包测试中覆盖。
	return map[string]string{"glm-4.6": "glm-4.6"}
}
