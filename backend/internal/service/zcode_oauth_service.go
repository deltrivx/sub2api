package service

// zcode_oauth_service.go — ZCode/Z.AI 的 CLI OAuth 登录流程。
//
// 移植自 zcode2api (https://github.com/liu5269/zcode2api) 的 app/oauth.py。
//
// 三步流程：
//  1. Init   —— 调用 /oauth/cli/init 拿到 flow_id 与授权 URL
//  2. Poll   —— 轮询 /oauth/cli/poll/{flow_id}，授权完成后返回 zcode JWT / zai access_token
//  3. Exchange —— 用 zai access_token 兑换业务 token，再创建/获取 API Key
//
// 本服务供后台账号导入 / CLI 登录使用；不参与网关请求路径（网关只读已落库的凭证）。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ZCodeOAuthService 封装 Z.AI CLI OAuth 流程。
type ZCodeOAuthService struct {
	httpClient *http.Client
}

// NewZCodeOAuthService 创建 OAuth 服务。httpClient 为 nil 时使用默认客户端。
func NewZCodeOAuthService(httpClient *http.Client) *ZCodeOAuthService {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &ZCodeOAuthService{httpClient: httpClient}
}

// ZCodeOAuthInit 是 OAuth 初始化结果。
type ZCodeOAuthInit struct {
	FlowID      string `json:"flow_id"`
	AuthorizeURL string `json:"authorize_url"`
}

// ZCodeOAuthPoll 是轮询结果。
type ZCodeOAuthPoll struct {
	Status string                 `json:"status"` // "pending" | "ready" | "failed"
	Token  string                 `json:"token"`  // zcode Coding Plan JWT（status=ready 时有值）
	ZAI    map[string]any         `json:"zai"`    // zai access_token 等
}

// Init 发起 OAuth 流程，返回 flow_id 与授权 URL。
func (s *ZCodeOAuthService) Init(ctx context.Context) (*ZCodeOAuthInit, error) {
	pollToken := randomHex(32)

	body := map[string]string{"provider": "zai"}
	resp, err := s.doJSON(ctx, http.MethodPost, ZCodeOAuthBase+"/oauth/cli/init", pollToken, body)
	if err != nil {
		return nil, err
	}
	defer drainAndClose(resp.Body)

	var wrapper struct {
		Data struct {
			FlowID       string `json:"flow_id"`
			AuthorizeURL string `json:"authorize_url"`
		} `json:"data"`
	}
	if err := decodeJSON(resp, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Data.FlowID == "" || wrapper.Data.AuthorizeURL == "" {
		return nil, fmt.Errorf("zcode oauth: incomplete init response")
	}
	return &ZCodeOAuthInit{FlowID: wrapper.Data.FlowID, AuthorizeURL: wrapper.Data.AuthorizeURL}, nil
}

// Poll 轮询 OAuth 授权状态。status="ready" 表示授权完成。
func (s *ZCodeOAuthService) Poll(ctx context.Context, flowID, pollToken string) (*ZCodeOAuthPoll, error) {
	resp, err := s.doJSON(ctx, http.MethodGet, ZCodeOAuthBase+"/oauth/cli/poll/"+flowID, pollToken, nil)
	if err != nil {
		return nil, err
	}
	defer drainAndClose(resp.Body)

	var wrapper struct {
		Data ZCodeOAuthPoll `json:"data"`
	}
	if err := decodeJSON(resp, &wrapper); err != nil {
		return nil, err
	}
	// 顶层 status 兜底：部分实现把 status 放在 data 同级
	if wrapper.Data.Status == "" {
		var top struct {
			Status string         `json:"status"`
			Data   map[string]any `json:"data"`
		}
		if err := decodeJSON(resp, &top); err == nil && top.Status != "" {
			wrapper.Data.Status = top.Status
		}
	}
	return &wrapper.Data, nil
}

// ExchangeAPIKey 用 zai access_token 兑换最终的 API Key（格式 apikey.secretkey）。
//
// 流程：access_token → /api/auth/z/login 取业务 token → getCustomerInfo 取机构/项目
//      → 创建/复用名为 "zcode-api-key" 的 API Key → copy 解密 secretKey。
func (s *ZCodeOAuthService) ExchangeAPIKey(ctx context.Context, accessToken string) (string, error) {
	bizToken, err := s.loginZAI(ctx, accessToken)
	if err != nil {
		return "", err
	}

	orgID, projectID, err := s.resolveDefaultOrgProject(ctx, bizToken)
	if err != nil {
		return "", err
	}

	apiKey, err := s.ensureAPIKey(ctx, bizToken, orgID, projectID)
	if err != nil {
		return "", err
	}

	secretKey, err := s.copyAPIKeySecret(ctx, bizToken, orgID, projectID, apiKey)
	if err != nil {
		return "", err
	}
	return apiKey + "." + secretKey, nil
}

// loginZAI 用 access_token 换取业务 token。
func (s *ZCodeOAuthService) loginZAI(ctx context.Context, accessToken string) (string, error) {
	body := map[string]string{"token": accessToken}
	resp, err := s.doJSON(ctx, http.MethodPost, ZCodeAPIAuthBase+"/api/auth/z/login", "", body)
	if err != nil {
		return "", err
	}
	defer drainAndClose(resp.Body)
	var wrapper struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			AccessToken2 string `json:"accessToken"`
		} `json:"data"`
	}
	if err := decodeJSON(resp, &wrapper); err != nil {
		return "", err
	}
	if wrapper.Data.AccessToken != "" {
		return wrapper.Data.AccessToken, nil
	}
	if wrapper.Data.AccessToken2 != "" {
		return wrapper.Data.AccessToken2, nil
	}
	return "", fmt.Errorf("zcode oauth: login response missing access_token")
}

// resolveDefaultOrgProject 取默认机构与默认项目。
func (s *ZCodeOAuthService) resolveDefaultOrgProject(ctx context.Context, bizToken string) (orgID, projectID string, err error) {
	resp, err := s.doJSON(ctx, http.MethodGet, ZCodeAPIAuthBase+"/api/biz/customer/getCustomerInfo", bizToken, nil)
	if err != nil {
		return "", "", err
	}
	defer drainAndClose(resp.Body)
	var wrapper struct {
		Data struct {
			Organizations []struct {
				OrganizationID string `json:"organizationId"`
				OrgName        string `json:"organizationName"`
				Projects       []struct {
					ProjectID string `json:"projectId"`
					ProjName  string `json:"projectName"`
				} `json:"projects"`
			} `json:"organizations"`
		} `json:"data"`
	}
	if err := decodeJSON(resp, &wrapper); err != nil {
		return "", "", err
	}
	orgs := wrapper.Data.Organizations
	if len(orgs) == 0 {
		return "", "", fmt.Errorf("zcode oauth: no organization available")
	}
	// 优先选名字含"默认机构"的，否则取第一个
	org := orgs[0]
	for _, o := range orgs {
		if strings.Contains(o.OrgName, "默认机构") {
			org = o
			break
		}
	}
	if len(org.Projects) == 0 {
		return "", "", fmt.Errorf("zcode oauth: no project available")
	}
	proj := org.Projects[0]
	for _, p := range org.Projects {
		if strings.Contains(p.ProjName, "默认项目") {
			proj = p
			break
		}
	}
	return org.OrganizationID, proj.ProjectID, nil
}

// ensureAPIKey 取名为 zcode-api-key 的 key，不存在则创建。
func (s *ZCodeOAuthService) ensureAPIKey(ctx context.Context, bizToken, orgID, projectID string) (string, error) {
	listURL := fmt.Sprintf("%s/api/biz/v1/organization/%s/projects/%s/api_keys", ZCodeAPIAuthBase, orgID, projectID)
	resp, err := s.doJSON(ctx, http.MethodGet, listURL, bizToken, nil)
	if err != nil {
		return "", err
	}
	var keysWrapper struct {
		Data []struct {
			Name    string `json:"name"`
			APIKey  string `json:"apiKey"`
			APIKey2 string `json:"ApiKey"`
		} `json:"data"`
	}
	if err := decodeJSON(resp, &keysWrapper); err != nil {
		drainAndClose(resp.Body)
		return "", err
	}
	drainAndClose(resp.Body)

	for _, k := range keysWrapper.Data {
		if k.Name == "zcode-api-key" {
			if k.APIKey != "" {
				return k.APIKey, nil
			}
			return k.APIKey2, nil
		}
	}

	// 创建
	createResp, err := s.doJSON(ctx, http.MethodPost, listURL, bizToken, map[string]string{"name": "zcode-api-key"})
	if err != nil {
		return "", err
	}
	defer drainAndClose(createResp.Body)
	var createWrapper struct {
		Data struct {
			APIKey  string `json:"apiKey"`
			APIKey2 string `json:"ApiKey"`
		} `json:"data"`
	}
	if err := decodeJSON(createResp, &createWrapper); err != nil {
		return "", err
	}
	if createWrapper.Data.APIKey != "" {
		return createWrapper.Data.APIKey, nil
	}
	return createWrapper.Data.APIKey2, nil
}

// copyAPIKeySecret 解密 API Key 的 secretKey。
func (s *ZCodeOAuthService) copyAPIKeySecret(ctx context.Context, bizToken, orgID, projectID, apiKey string) (string, error) {
	url := fmt.Sprintf("%s/api/biz/v1/organization/%s/projects/%s/api_keys/copy/%s", ZCodeAPIAuthBase, orgID, projectID, apiKey)
	resp, err := s.doJSON(ctx, http.MethodGet, url, bizToken, nil)
	if err != nil {
		return "", err
	}
	defer drainAndClose(resp.Body)
	var wrapper struct {
		Data struct {
			SecretKey string `json:"secretKey"`
		} `json:"data"`
	}
	if err := decodeJSON(resp, &wrapper); err != nil {
		return "", err
	}
	if wrapper.Data.SecretKey == "" {
		return "", fmt.Errorf("zcode oauth: failed to decrypt secret key")
	}
	return wrapper.Data.SecretKey, nil
}

// ── HTTP 工具方法 ───────────────────────────────────────────────────────────

func (s *ZCodeOAuthService) doJSON(ctx context.Context, method, url, bearer string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("zcode oauth: marshal body: %w", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("zcode oauth: new request: %w", err)
	}
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return s.httpClient.Do(req)
}

func decodeJSON(resp *http.Response, v any) error {
	if resp.StatusCode >= 400 {
		return fmt.Errorf("zcode oauth: upstream %s returned HTTP %d", resp.Request.URL, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func drainAndClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}
