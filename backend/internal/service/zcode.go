package service

// zcode.go — ZCode/Z.AI 提供商的常量、上游端点与请求头构建。
//
// 移植自 zcode2api (https://github.com/liu5269/zcode2api) 的 app/agent.py 与
// app/settings.py，适配 sub2api 的账号模型。
//
// ZCode 兼容 Anthropic Messages 协议，请求体无需改写，仅需在上游请求上附加
// ZCode 专有头部（X-ZCode-App-Version / X-ZCode-Agent / X-Aliyun-Captcha-Verify-Param）。

import (
	"os"
	"strings"
)

// ── 上游端点 ──────────────────────────────────────────────────────────────────
//
// 可通过环境变量覆盖，默认值与 zcode2api 保持一致。

// ZCodeUpstreamURL 为 Coding Plan (JWT) 账号使用的上游 Anthropic Messages 端点。
func ZCodeUpstreamURL() string {
	if v := strings.TrimSpace(os.Getenv("ZCODE_UPSTREAM_URL")); v != "" {
		return v
	}
	return "https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages"
}

// ZCodeFallbackURL 为 API Key 账号使用的回退上游端点。
func ZCodeFallbackURL() string {
	if v := strings.TrimSpace(os.Getenv("ZCODE_FALLBACK_URL")); v != "" {
		return v
	}
	return "https://api.z.ai/api/anthropic/v1/messages"
}

// ZCodeBillingBase 为 ZCode 计费 / 额度查询端点。
const ZCodeBillingBase = "https://zcode.z.ai/api/v1/zcode-plan"

// ZCodeOAuthBase 为 Z.AI CLI OAuth 流程的基础地址。
const ZCodeOAuthBase = "https://zcode.z.ai/api/v1"

// ZCodeAPIAuthBase 为 OAuth access_token 兑换业务凭证 / API Key 的基础地址。
const ZCodeAPIAuthBase = "https://api.z.ai"

// ── 请求头 ────────────────────────────────────────────────────────────────────

// ZCodeUserAgent ZCode 上游默认 User-Agent。
func ZCodeUserAgent() string {
	if v := strings.TrimSpace(os.Getenv("UPSTREAM_USER_AGENT")); v != "" {
		return v
	}
	return "ZCode/3.0.1"
}

// ZCodeAppVersion 透传给上游的 X-ZCode-App-Version。
const ZCodeAppVersion = "3.0.1"

// ZCodeAgent 透传给上游的 X-ZCode-Agent。
const ZCodeAgent = "glm"

// ZCodeReferer 透传给上游的 HTTP-Referer。
const ZCodeReferer = "https://zcode.z.ai/"

// ZCodeAnthropicVersion ZCode 上游使用的 anthropic-version。
const ZCodeAnthropicVersion = "2023-06-01"

// zcodeDropHeaders 透传客户端头部时需要剔除的字段（小写匹配）。
var zcodeDropHeaders = map[string]struct{}{
	"host":            {},
	"content-length":  {},
	"x-api-key":       {},
	"authorization":   {},
	"user-agent":      {},
	"http-referer":    {},
	"accept-encoding": {},
	"connection":      {},
}

// ZCodeBuildHeaders 根据 ZCode 账号凭证构建上游请求头。
//
//   - mode="oauth"（JWT）  : 走 ZCodeUpstreamURL，使用 Authorization: Bearer <jwt>
//   - mode="apikey"        : 走 ZCodeFallbackURL，使用 x-api-key: <key>
//
// verifyParam 为阿里云无痕验证参数；OAuth(JWT) 模式调用上游时需要，API Key 模式可空。
// incomingHeaders 为客户端原始请求头，按需透传（剔除受控头部与 x-zcode-* 前缀）。
//
// 返回 (目标 URL, 请求头 map)。
func ZCodeBuildHeaders(mode, secret, verifyParam string, incomingHeaders map[string]string) (string, map[string]string) {
	var targetURL, authHeader, authValue string
	switch mode {
	case "oauth":
		targetURL = ZCodeUpstreamURL()
		authHeader, authValue = "Authorization", "Bearer "+secret
	case "apikey":
		targetURL = ZCodeFallbackURL()
		authHeader, authValue = "x-api-key", secret
	default:
		// 未知模式兜底走 apikey 回退端点，避免把无凭证请求打到需验证码的 JWT 端点。
		targetURL = ZCodeFallbackURL()
		authHeader, authValue = "x-api-key", secret
	}

	headers := map[string]string{
		"content-type":         "application/json",
		"anthropic-version":    ZCodeAnthropicVersion,
		"User-Agent":           ZCodeUserAgent(),
		"X-ZCode-App-Version":  ZCodeAppVersion,
		"X-ZCode-Agent":        ZCodeAgent,
		"HTTP-Referer":         ZCodeReferer,
		authHeader:             authValue,
	}
	if verifyParam != "" {
		headers["X-Aliyun-Captcha-Verify-Param"] = verifyParam
	}

	for key, value := range incomingHeaders {
		lower := strings.ToLower(key)
		if _, drop := zcodeDropHeaders[lower]; drop {
			continue
		}
		if strings.HasPrefix(lower, "x-zcode") {
			continue
		}
		headers[key] = value
	}
	return targetURL, headers
}
