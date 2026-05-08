package npm

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func isJSONContentType(contentType string) bool {
	mediaType, _, _ := strings.Cut(contentType, ";")
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func rewriteMetadataTarballs(r *http.Request, body io.Reader, tenantID, upstreamID string) ([]byte, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}

	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}

	proxyBase := npmProxyBaseURL(r, tenantID, upstreamID)
	rewriteTarballURLs(payload, proxyBase)

	rewritten, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return rewritten, nil
}

func rewriteTarballURLs(value any, proxyBase string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			rewriteTarballURLs(child, proxyBase)
			if key != "tarball" {
				continue
			}
			tarball, ok := child.(string)
			if !ok || strings.TrimSpace(tarball) == "" {
				continue
			}
			typed[key] = proxyBase + strings.TrimPrefix(tarballPath(tarball), "/")
		}
	case []any:
		for _, child := range typed {
			rewriteTarballURLs(child, proxyBase)
		}
	}
}

func tarballPath(tarballURL string) string {
	parsed, err := url.Parse(tarballURL)
	if err != nil {
		return tarballURL
	}
	if parsed.RawPath != "" {
		return parsed.RawPath
	}
	if parsed.Path != "" {
		return parsed.Path
	}
	return tarballURL
}

func npmProxyBaseURL(r *http.Request, tenantID, upstreamID string) string {
	base := requestBaseURL(r)
	var path strings.Builder
	path.WriteString("/npm/t/")
	path.WriteString(tenantID)
	path.WriteByte('/')
	if upstreamID != "" {
		path.WriteString("u/")
		path.WriteString(upstreamID)
		path.WriteByte('/')
	}
	return strings.TrimRight(base, "/") + path.String()
}

func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwardedProto := firstHeaderValue(r.Header.Get("X-Forwarded-Proto")); forwardedProto != "" {
		scheme = forwardedProto
	}

	host := firstHeaderValue(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}

	return scheme + "://" + host
}

func firstHeaderValue(value string) string {
	if value == "" {
		return ""
	}
	part, _, _ := strings.Cut(value, ",")
	return strings.TrimSpace(part)
}
