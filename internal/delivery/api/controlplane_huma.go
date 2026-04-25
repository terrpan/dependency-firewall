package api

import (
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

const (
	controlPlaneDocsPath    = "/api/docs"
	controlPlaneOpenAPIPath = "/api/openapi"
)

var configureHumaErrors sync.Once

var unexpectedPropertyPattern = regexp.MustCompile(`unexpected property`)

type humaErrorResponse struct {
	status  int
	Message string `json:"error"`
}

func (e *humaErrorResponse) Error() string {
	return e.Message
}

func (e *humaErrorResponse) GetStatus() int {
	return e.status
}

func (e *humaErrorResponse) ContentType(contentType string) string {
	return "application/json"
}

// NewControlPlaneAPI creates a Huma API for control-plane documentation and
// incremental control-plane routes only.
func NewControlPlaneAPI(mux *http.ServeMux, version string) huma.API {
	configureHumaErrors.Do(func() {
		huma.NewError = func(status int, msg string, errs ...error) huma.StatusError {
			status, message := formatHumaError(status, msg, errs)
			if message == "" {
				message = http.StatusText(status)
			}
			return &humaErrorResponse{
				status:  status,
				Message: message,
			}
		}

		huma.NewErrorWithContext = func(_ huma.Context, status int, msg string, errs ...error) huma.StatusError {
			return huma.NewError(status, msg, errs...)
		}
	})

	config := huma.DefaultConfig("dependency-firewall control-plane API", version)
	config.OpenAPIPath = controlPlaneOpenAPIPath
	config.DocsPath = controlPlaneDocsPath
	config.SchemasPath = ""
	config.Transformers = nil
	config.CreateHooks = nil

	return humago.New(mux, config)
}

func removeValidationResponse(api huma.API, path string, methods ...string) {
	pathItem := api.OpenAPI().Paths[path]
	if pathItem == nil {
		return
	}

	for _, method := range methods {
		operation := pathOperation(pathItem, method)
		if operation == nil || operation.Responses == nil {
			continue
		}
		delete(operation.Responses, "422")
	}
}

func setRequestBodyContentTypes(api huma.API, path, method string, contentTypes ...string) {
	pathItem := api.OpenAPI().Paths[path]
	if pathItem == nil {
		return
	}

	operation := pathOperation(pathItem, method)
	if operation == nil || operation.RequestBody == nil || len(contentTypes) == 0 {
		return
	}

	var template *huma.MediaType
	for _, mediaType := range operation.RequestBody.Content {
		template = mediaType
		break
	}
	if template == nil {
		return
	}

	content := make(map[string]*huma.MediaType, len(contentTypes))
	for _, contentType := range contentTypes {
		copyMediaType := *template
		content[contentType] = &copyMediaType
	}
	operation.RequestBody.Content = content
}

func pathOperation(pathItem *huma.PathItem, method string) *huma.Operation {
	switch strings.ToUpper(method) {
	case http.MethodGet:
		return pathItem.Get
	case http.MethodPost:
		return pathItem.Post
	case http.MethodPut:
		return pathItem.Put
	case http.MethodDelete:
		return pathItem.Delete
	case http.MethodPatch:
		return pathItem.Patch
	default:
		return nil
	}
}

func formatHumaError(status int, msg string, errs []error) (int, string) {
	message := strings.TrimSpace(msg)
	if len(errs) == 0 {
		return status, message
	}

	firstDetail, ok := firstErrorDetail(errs)
	if !ok {
		if isGenericHumaError(message) {
			for _, err := range errs {
				if err == nil {
					continue
				}
				return status, strings.TrimSpace(err.Error())
			}
		}
		return status, message
	}

	if strings.HasPrefix(firstDetail.Location, "body") {
		if status == http.StatusUnprocessableEntity {
			status = http.StatusBadRequest
		}
		return status, simplifyBodyError(firstDetail)
	}

	if isGenericHumaError(message) {
		message = firstDetail.Message
	}

	return status, strings.TrimSpace(message)
}

func firstErrorDetail(errs []error) (*huma.ErrorDetail, bool) {
	for _, err := range errs {
		if err == nil {
			continue
		}
		detailer, ok := err.(huma.ErrorDetailer)
		if !ok {
			continue
		}
		detail := detailer.ErrorDetail()
		if detail == nil {
			continue
		}
		return detail, true
	}
	return nil, false
}

func simplifyBodyError(detail *huma.ErrorDetail) string {
	message := strings.TrimSpace(detail.Message)
	if message == "" {
		return "invalid JSON"
	}

	if unexpectedPropertyPattern.MatchString(message) {
		field := lastLocationPart(detail.Location)
		if field != "" {
			return `invalid JSON: unknown field "` + field + `"`
		}
	}

	return "invalid JSON: " + message
}

func lastLocationPart(location string) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}
	parts := strings.Split(location, ".")
	return parts[len(parts)-1]
}

func isGenericHumaError(message string) bool {
	switch message {
	case "", "validation failed", "unable to decode request body", "unexpected error occurred":
		return true
	default:
		return false
	}
}
