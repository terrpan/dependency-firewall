package main

import (
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"

	deliveryapi "github.com/danielterry/dependency-firewall/internal/delivery/api"
)

func main() {
	mux := http.NewServeMux()
	controlPlaneAPI := deliveryapi.NewControlPlaneAPI(mux, "dev")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	deliveryapi.NewHealthHandler(nil, logger).RegisterHumaRoutes(controlPlaneAPI)
	deliveryapi.NewTenantHandler(nil, logger).RegisterHumaRoutes(controlPlaneAPI)
	deliveryapi.NewPolicyHandler(nil, logger).RegisterHumaRoutes(controlPlaneAPI)
	deliveryapi.NewCacheHandler(nil, logger).RegisterHumaRoutes(controlPlaneAPI)
	deliveryapi.NewUpstreamHandler(nil, logger).RegisterHumaRoutes(controlPlaneAPI)
	deliveryapi.NewEvaluationHandler(nil, logger).RegisterHumaRoutes(controlPlaneAPI)

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(controlPlaneAPI.OpenAPI()); err != nil {
		log.Fatalf("encode OpenAPI spec: %v", err)
	}
}
