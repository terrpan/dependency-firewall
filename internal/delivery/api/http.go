package api

import (
	"fmt"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/validation"
)

var requestValidator = validation.New("json")

func tenantIDFromValue(value string) (string, error) {
	id := strings.TrimSpace(value)
	if id == "" {
		return "", fmt.Errorf("missing X-Tenant-ID header")
	}
	return id, nil
}

func validateRequest(req any) error {
	if err := requestValidator.Struct(req); err != nil {
		return fmt.Errorf("invalid request: %s", validation.ErrorMessage(err))
	}
	return nil
}
