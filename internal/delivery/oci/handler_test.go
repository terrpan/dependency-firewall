package oci

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteOCIError_GetIncludesBodyAndReasonHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v2/library/nginx/manifests/latest", nil)
	rec := httptest.NewRecorder()

	writeOCIError(rec, req, "DENIED", `policy violation: policy "block-mutable-tags" denied: mutable tag "latest" is not allowed`, http.StatusForbidden)

	res := rec.Result()
	defer res.Body.Close()

	require.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.Equal(t, "registry/2.0", res.Header.Get("Docker-Distribution-Api-Version"))
	assert.Equal(t, `policy violation: policy "block-mutable-tags" denied: mutable tag "latest" is not allowed`, res.Header.Get("X-Dependency-Firewall-Reason"))

	var body ociErrorResponse
	require.NoError(t, json.NewDecoder(res.Body).Decode(&body))
	require.Len(t, body.Errors, 1)
	assert.Equal(t, "DENIED", body.Errors[0].Code)
	assert.Equal(t, `policy violation: policy "block-mutable-tags" denied: mutable tag "latest" is not allowed`, body.Errors[0].Message)
}

func TestWriteOCIError_HeadOmitsBodyButKeepsReasonHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodHead, "/v2/library/nginx/manifests/latest", nil)
	rec := httptest.NewRecorder()

	writeOCIError(rec, req, "DENIED", `policy violation: policy "block-mutable-tags" denied: mutable tag "latest" is not allowed`, http.StatusForbidden)

	res := rec.Result()
	defer res.Body.Close()

	require.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.Equal(t, "registry/2.0", res.Header.Get("Docker-Distribution-Api-Version"))
	assert.Equal(t, `policy violation: policy "block-mutable-tags" denied: mutable tag "latest" is not allowed`, res.Header.Get("X-Dependency-Firewall-Reason"))
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Empty(t, body)
}
