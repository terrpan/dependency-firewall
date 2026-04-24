package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/validation"
)

var requestValidator = validation.New("json")

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "encoding response", http.StatusInternalServerError)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func readJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return fmt.Errorf("empty request body")
	}
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("invalid JSON: unexpected trailing data")
		}
		return fmt.Errorf("invalid JSON: %w", err)
	}

	return nil
}

func tenantIDFromHeader(r *http.Request) (string, error) {
	id := strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
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
