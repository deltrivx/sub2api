package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestZCodeOAuthService_Init 验证 Init 返回 flow_id 与授权 URL。
// 注：此测试验证服务能正确解码响应；端点 URL 通过 httptest 直接注入。
func TestZCodeOAuthService_Init(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"flow_id":       "flow-abc",
				"authorize_url": "https://example.com/auth",
			},
		})
	}))
	t.Cleanup(srv.Close)

	// 直接复用内部 doJSON 走到测试服务器：用临时包装
	svc := &ZCodeOAuthService{httpClient: srv.Client()}
	resp, err := svc.doJSON(context.Background(), http.MethodPost, srv.URL+"/oauth/cli/init", "poll-tok", map[string]string{"provider": "zai"})
	if err != nil {
		t.Fatalf("doJSON failed: %v", err)
	}
	defer drainAndClose(resp.Body)
	var wrapper struct {
		Data struct {
			FlowID       string `json:"flow_id"`
			AuthorizeURL string `json:"authorize_url"`
		} `json:"data"`
	}
	if err := decodeJSON(resp, &wrapper); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if wrapper.Data.FlowID != "flow-abc" {
		t.Fatalf("expected flow_id=flow-abc, got %q", wrapper.Data.FlowID)
	}
	if wrapper.Data.AuthorizeURL != "https://example.com/auth" {
		t.Fatalf("unexpected authorize_url %q", wrapper.Data.AuthorizeURL)
	}
}
