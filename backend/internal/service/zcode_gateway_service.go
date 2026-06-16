package service

// zcode_gateway_service.go — ZCode/Z.AI 平台的网关转发适配。
//
// ZCode 兼容 Anthropic Messages 协议，请求体与 Anthropic 完全一致，
// 仅需把上游请求指向 ZCode 端点并附加 ZCode 专有头部
// （X-ZCode-App-Version / X-ZCode-Agent / HTTP-Referer / 阿里云无痕验证参数）。
//
// 本文件实现 buildUpstreamRequestZCode，由 buildUpstreamRequest 在识别到
// PlatformZCode 时调用，完全绕开 Anthropic 的指纹 / CCH / mimicry 链路。

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// buildUpstreamRequestZCode 为 ZCode 账号构建上游 HTTP 请求。
//
//   - 凭证模式由账号类型决定（见 ZCodeResolveModeAndSecret）
//   - 请求头由 ZCodeBuildHeaders 生成，附加 ZCode 专有头部
//   - verifyParam 暂留空（阿里云无痕验证参数由阶段3的 Node 求解器子进程提供）
//
// 返回的 *http.Request 由 GatewayService.Forward 统一发送，与 Anthropic 路径一致。
func (s *GatewayService) buildUpstreamRequestZCode(ctx context.Context, c *gin.Context, account *Account, body []byte) (*http.Request, error) {
	mode, secret := ZCodeResolveModeAndSecret(account)
	if secret == "" {
		return nil, fmt.Errorf("zcode account %d: missing credential (type=%s)", account.ID, account.Type)
	}

	// 客户端原始请求头，按需透传（ZCodeBuildHeaders 内部剔除受控头部）。
	incoming := make(map[string]string)
	if c != nil && c.Request != nil {
		for key, vals := range c.Request.Header {
			if len(vals) > 0 {
				incoming[key] = vals[0]
			}
		}
	}

	// 阿里云无痕验证参数：OAuth(JWT) 模式调用 ZCode 上游时需要。
	// 阶段3接入 Node 求解器子进程后，由 ZCodeCaptchaSolver.Solve() 提供。
	verifyParam := ""

	targetURL, headers := ZCodeBuildHeaders(mode, secret, verifyParam, incoming)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("zcode build request: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req, nil
}
