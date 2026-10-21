package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestWithCORS(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := withCORS(next, []string{"http://localhost:8081"})

	tests := []struct {
		name        string
		method      string
		origin      string
		wantStatus  int
		wantAllowed string
	}{
		{"allowed preflight", http.MethodOptions, "http://localhost:8081", http.StatusNoContent, "http://localhost:8081"},
		{"other-origin preflight", http.MethodOptions, "http://evil.example", http.StatusForbidden, ""},
		{"allowed request", http.MethodPost, "http://localhost:8081", http.StatusOK, "http://localhost:8081"},
		{"other-origin request", http.MethodPost, "http://evil.example", http.StatusOK, ""},
		{"no origin", http.MethodPost, "", http.StatusOK, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/operations", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tt.wantAllowed {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, tt.wantAllowed)
			}
			if got := rec.Header().Get("Vary"); got != "Origin" {
				t.Errorf("Vary = %q, want Origin", got)
			}
		})
	}
}

func TestSplitList(t *testing.T) {
	got := splitList(" http://a , ,http://b,")
	want := []string{"http://a", "http://b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitList = %v, want %v", got, want)
	}
}
