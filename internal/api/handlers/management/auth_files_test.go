package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestDeleteAuthFile_FailedOnly(t *testing.T) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	failedPath := filepath.Join(authDir, "failed.json")
	healthyPath := filepath.Join(authDir, "healthy.json")
	if err := os.WriteFile(failedPath, []byte(`{"type":"gemini"}`), 0o600); err != nil {
		t.Fatalf("write failed auth file: %v", err)
	}
	if err := os.WriteFile(healthyPath, []byte(`{"type":"gemini"}`), 0o600); err != nil {
		t.Fatalf("write healthy auth file: %v", err)
	}

	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)

	failedAuth := &coreauth.Auth{
		ID:          "failed.json",
		FileName:    "failed.json",
		Provider:    "gemini",
		Status:      coreauth.StatusError,
		Unavailable: true,
		Attributes: map[string]string{
			"path": failedPath,
		},
		Metadata: map[string]any{"type": "gemini"},
	}
	healthyAuth := &coreauth.Auth{
		ID:       "healthy.json",
		FileName: "healthy.json",
		Provider: "gemini",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"path": healthyPath,
		},
		Metadata: map[string]any{"type": "gemini"},
	}
	if _, err := manager.Register(context.Background(), failedAuth); err != nil {
		t.Fatalf("register failed auth: %v", err)
	}
	if _, err := manager.Register(context.Background(), healthyAuth); err != nil {
		t.Fatalf("register healthy auth: %v", err)
	}

	h := &Handler{
		cfg:         &config.Config{AuthDir: authDir},
		authManager: manager,
		tokenStore:  store,
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/v0/management/auth-files?failed=true", nil)
	h.DeleteAuthFile(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, _ := resp["deleted"].(float64); got != 1 {
		t.Fatalf("expected deleted=1, got %v", resp["deleted"])
	}
	if _, err := os.Stat(failedPath); !os.IsNotExist(err) {
		t.Fatalf("expected failed file removed, err=%v", err)
	}
	if _, err := os.Stat(healthyPath); err != nil {
		t.Fatalf("expected healthy file retained, err=%v", err)
	}
}

func TestDeleteAuthFile_FailedOnlySkipsFilesOutsideAuthDir(t *testing.T) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	outsideDir := t.TempDir()
	outsidePath := filepath.Join(outsideDir, "outside.json")
	if err := os.WriteFile(outsidePath, []byte(`{"type":"gemini"}`), 0o600); err != nil {
		t.Fatalf("write outside auth file: %v", err)
	}

	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)
	outsideAuth := &coreauth.Auth{
		ID:          "outside.json",
		FileName:    "outside.json",
		Provider:    "gemini",
		Status:      coreauth.StatusError,
		Unavailable: true,
		Attributes: map[string]string{
			"path": outsidePath,
		},
		Metadata: map[string]any{"type": "gemini"},
	}
	if _, err := manager.Register(context.Background(), outsideAuth); err != nil {
		t.Fatalf("register outside auth: %v", err)
	}

	h := &Handler{
		cfg:         &config.Config{AuthDir: authDir},
		authManager: manager,
		tokenStore:  store,
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/v0/management/auth-files?failed=true", nil)
	h.DeleteAuthFile(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, _ := resp["deleted"].(float64); got != 0 {
		t.Fatalf("expected deleted=0, got %v", resp["deleted"])
	}
	if _, err := os.Stat(outsidePath); err != nil {
		t.Fatalf("expected outside file retained, err=%v", err)
	}
}

func TestDeleteAuthFile_InvalidOnly(t *testing.T) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	invalidPath := filepath.Join(authDir, "invalid.json")
	validPath := filepath.Join(authDir, "valid.json")
	if err := os.WriteFile(invalidPath, []byte(`{"type":"codex"}`), 0o600); err != nil {
		t.Fatalf("write invalid auth file: %v", err)
	}
	if err := os.WriteFile(validPath, []byte(`{"type":"codex"}`), 0o600); err != nil {
		t.Fatalf("write valid auth file: %v", err)
	}

	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)

	invalidAuth := &coreauth.Auth{
		ID:       "invalid.json",
		FileName: "invalid.json",
		Provider: "codex",
		Status:   coreauth.StatusError,
		Attributes: map[string]string{
			"path": invalidPath,
		},
		Metadata: map[string]any{
			"type":                 "codex",
			tokenInvalidMetaKey:    true,
			tokenInvalidReasonKey:  "refresh failed",
			tokenInvalidAtKey:      "2026-02-18T00:00:00Z",
			"access_token":         "expired",
			"refresh_token":        "expired",
			"chatgpt_account_id":   "test-account",
			"chatgpt_plan_type":    "plus",
			"chatgpt_subscription": "active",
		},
	}
	validAuth := &coreauth.Auth{
		ID:       "valid.json",
		FileName: "valid.json",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"path": validPath,
		},
		Metadata: map[string]any{
			"type": "codex",
		},
	}
	if _, err := manager.Register(context.Background(), invalidAuth); err != nil {
		t.Fatalf("register invalid auth: %v", err)
	}
	if _, err := manager.Register(context.Background(), validAuth); err != nil {
		t.Fatalf("register valid auth: %v", err)
	}

	h := &Handler{
		cfg:         &config.Config{AuthDir: authDir},
		authManager: manager,
		tokenStore:  store,
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/v0/management/auth-files?invalid=true", nil)
	h.DeleteAuthFile(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, _ := resp["deleted"].(float64); got != 1 {
		t.Fatalf("expected deleted=1, got %v", resp["deleted"])
	}
	if got, _ := resp["matched"].(float64); got != 1 {
		t.Fatalf("expected matched=1, got %v", resp["matched"])
	}
	if _, err := os.Stat(invalidPath); !os.IsNotExist(err) {
		t.Fatalf("expected invalid file removed, err=%v", err)
	}
	if _, err := os.Stat(validPath); err != nil {
		t.Fatalf("expected valid file retained, err=%v", err)
	}
}

func TestVerifyInvalidAuthFiles_CodexMarks401AsInvalid(t *testing.T) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)

	auth := &coreauth.Auth{
		ID:       "codex-401.json",
		FileName: "codex-401.json",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{
			"type":         "codex",
			"access_token": "live-token",
			"expired":      "2099-01-01T00:00:00Z",
			"account_id":   "acct-401",
		},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer live-token" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		if got := r.Header.Get("Chatgpt-Account-Id"); got != "acct-401" {
			t.Fatalf("unexpected account header: %q", got)
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"account_deactivated"}}`))
	}))
	t.Cleanup(srv.Close)

	originalProbeURL := codexUsageProbeURL
	codexUsageProbeURL = srv.URL
	t.Cleanup(func() {
		codexUsageProbeURL = originalProbeURL
	})

	h := &Handler{
		cfg:         &config.Config{AuthDir: authDir},
		authManager: manager,
		tokenStore:  store,
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/verify-invalid?provider=codex", nil)
	h.VerifyInvalidAuthFiles(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, _ := resp["invalid"].(float64); got != 1 {
		t.Fatalf("expected invalid=1, got %v", resp["invalid"])
	}

	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("missing auth after verify")
	}
	invalid, reason := tokenInvalidState(updated)
	if !invalid {
		t.Fatalf("expected auth marked invalid")
	}
	if !strings.Contains(reason, "401") {
		t.Fatalf("expected reason contains 401, got %q", reason)
	}
}

func TestVerifyInvalidAuthFiles_CodexClearsInvalidOn2xx(t *testing.T) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)

	auth := &coreauth.Auth{
		ID:       "codex-200.json",
		FileName: "codex-200.json",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{
			"type":                 "codex",
			"access_token":         "ok-token",
			"expired":              "2099-01-01T00:00:00Z",
			tokenInvalidMetaKey:    true,
			tokenInvalidReasonKey:  "old reason",
			tokenInvalidAtKey:      "2026-02-18T00:00:00Z",
			"chatgpt_account_id":   "acct-200",
			"chatgpt_plan_type":    "plus",
			"chatgpt_subscription": "active",
		},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer ok-token" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		if got := r.Header.Get("Chatgpt-Account-Id"); got != "acct-200" {
			t.Fatalf("unexpected account header: %q", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"plan_type":"free"}`))
	}))
	t.Cleanup(srv.Close)

	originalProbeURL := codexUsageProbeURL
	codexUsageProbeURL = srv.URL
	t.Cleanup(func() {
		codexUsageProbeURL = originalProbeURL
	})

	h := &Handler{
		cfg:         &config.Config{AuthDir: authDir},
		authManager: manager,
		tokenStore:  store,
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/verify-invalid?provider=codex", nil)
	h.VerifyInvalidAuthFiles(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, _ := resp["valid"].(float64); got != 1 {
		t.Fatalf("expected valid=1, got %v", resp["valid"])
	}
	if got, _ := resp["invalid"].(float64); got != 0 {
		t.Fatalf("expected invalid=0, got %v", resp["invalid"])
	}

	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("missing auth after verify")
	}
	invalid, reason := tokenInvalidState(updated)
	if invalid {
		t.Fatalf("expected auth marked valid")
	}
	if reason != "" {
		t.Fatalf("expected empty reason after success, got %q", reason)
	}
}
