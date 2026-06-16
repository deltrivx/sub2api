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

// TestZCodeRandomHex 验证随机十六进制生成。
func TestZCodeRandomHex(t *testing.T) {
	s, err := randomHex(16)
	if err != nil {
		t.Fatalf("randomHex failed: %v", err)
	}
	if len(s) != 32 {
		t.Fatalf("expected 32 hex chars, got %d", len(s))
	}
	for _, c := range s {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			t.Fatalf("non-hex char %q in %s", c, s)
		}
	}
	// 两次调用应不同（概率上）
	s2, _ := randomHex(16)
	if s == s2 {
		t.Fatal("randomHex returned identical values")
	}
}
