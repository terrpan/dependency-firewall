package api

import (
	"errors"
	"mime"
	"strings"
)

func parseMediaType(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return "", errors.New("invalid Content-Type header")
	}
	return mediaType, nil
}

func isSupportedPolicyImportContentType(mediaType string) bool {
	switch mediaType {
	case "application/json", "application/x-yaml", "application/yaml", "text/yaml", "text/x-yaml":
		return true
	default:
		return false
	}
}

func trimOptionalString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}
