package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"log/slog"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Enrich(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name          string
		artifact      domain.ArtifactIdentity
		handler       http.HandlerFunc
		wantErr       bool
		wantErrIs     error
		wantVulnCount int
		wantMaxCVSS   *float64
		wantNilResult bool
	}{
		{
			name: "successful query returns vulnerabilities with vector CVSS scores",
			artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemNPM,
				Namespace: "@babel",
				Name:      "core",
				Version:   "7.0.0",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

				var req queryRequest
				err := json.NewDecoder(r.Body).Decode(&req)
				require.NoError(t, err)
				assert.Equal(t, "@babel/core", req.Package.Name)
				assert.Equal(t, "npm", req.Package.Ecosystem)
				assert.Equal(t, "7.0.0", req.Version)

				resp := queryResponse{
					Vulns: []osvVuln{
						{
							ID:      "GHSA-1234",
							Summary: "Critical vulnerability",
							Severity: []osvSeverity{
								{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
							},
						},
						{
							ID:      "GHSA-5678",
							Summary: "Medium vulnerability",
							Severity: []osvSeverity{
								{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:H/SI:H/SA:H/E:P"},
							},
						},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			wantVulnCount: 2,
			wantMaxCVSS:   new(9.8),
		},
		{
			name: "empty vulns response returns metadata with nil MaxCVSS",
			artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemNPM,
				Name:      "safe-package",
				Version:   "1.0.0",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := queryResponse{Vulns: nil}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			wantVulnCount: 0,
			wantMaxCVSS:   nil,
		},
		{
			name: "OCI ecosystem returns empty metadata",
			artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemOCI,
				Namespace: "library",
				Name:      "nginx",
				Version:   "latest",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				t.Fatal("handler should not be called for OCI")
			},
			wantVulnCount: 0,
			wantMaxCVSS:   nil,
		},
		{
			name: "API error 500 returns ErrEnrichmentFailed",
			artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemNPM,
				Name:      "some-package",
				Version:   "1.0.0",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr:   true,
			wantErrIs: domain.ErrEnrichmentFailed,
		},
		{
			name: "rate limit 429 returns ErrEnrichmentFailed",
			artifact: domain.ArtifactIdentity{
				Ecosystem: domain.EcosystemNPM,
				Name:      "some-package",
				Version:   "1.0.0",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
			},
			wantErr:   true,
			wantErrIs: domain.ErrEnrichmentFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var server *httptest.Server
			if tc.handler != nil {
				server = httptest.NewServer(tc.handler)
				defer server.Close()
			}

			client := NewClient(nil, logger)
			if server != nil {
				client.baseURL = server.URL
			}

			result, err := client.Enrich(context.Background(), tc.artifact)

			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErrIs)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Len(t, result.Vulnerabilities, tc.wantVulnCount)

			if tc.wantMaxCVSS != nil {
				require.NotNil(t, result.MaxCVSS)
				assert.InDelta(t, *tc.wantMaxCVSS, *result.MaxCVSS, 0.01)
			} else {
				assert.Nil(t, result.MaxCVSS)
			}
		})
	}
}

func TestParseCVSSScore(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  float64
	}{
		{name: "plain numeric score", input: "9.8", want: 9.8},
		{name: "cvss 3.0 vector", input: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", want: 9.8},
		{name: "cvss 3.1 vector", input: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", want: 9.8},
		{name: "cvss 4.0 vector", input: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:H/SI:H/SA:H/E:P", want: 6.9},
		{name: "invalid vector", input: "CVSS:3.1/not-a-vector", want: 0},
		{name: "empty", input: "", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.InDelta(t, tt.want, parseCVSSScore(tt.input), 0.01)
		})
	}
}

func TestClient_Enrich_Timeout(t *testing.T) {
	logger := slog.Default()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer server.Close()

	httpClient := &http.Client{Timeout: 100 * time.Millisecond}
	client := NewClient(httpClient, logger)
	client.baseURL = server.URL

	artifact := domain.ArtifactIdentity{
		Ecosystem: domain.EcosystemNPM,
		Name:      "slow-package",
		Version:   "1.0.0",
	}

	_, err := client.Enrich(context.Background(), artifact)
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrEnrichmentFailed)
}

//go:fix inline
func ptr(f float64) *float64 {
	return new(f)
}
