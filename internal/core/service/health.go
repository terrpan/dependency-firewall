package service

import (
	"context"
	"log/slog"
	"runtime"
	"time"
)

// HealthChecker abstracts a dependency that can be pinged.
type HealthChecker interface {
	Ping(ctx context.Context) error
}

// HealthService checks the health of the service and its dependencies.
type HealthService struct {
	serviceName  string
	version      string
	commit       string
	buildTime    string
	dbChecker    HealthChecker
	cacheChecker HealthChecker
	logger       *slog.Logger
}

// NewHealthService creates a new HealthService.
func NewHealthService(
	serviceName, version, commit, buildTime string,
	dbChecker, cacheChecker HealthChecker,
	logger *slog.Logger,
) *HealthService {
	return &HealthService{
		serviceName:  serviceName,
		version:      version,
		commit:       commit,
		buildTime:    buildTime,
		dbChecker:    dbChecker,
		cacheChecker: cacheChecker,
		logger:       logger,
	}
}

// HealthStatus reports the health of the service and its dependencies.
type HealthStatus struct {
	Status       string
	ServiceName  string
	Version      string
	Commit       string
	BuildTime    string
	GoVersion    string
	OS           string
	Arch         string
	Timestamp    time.Time
	Dependencies map[string]DependencyStatus
}

// DependencyStatus holds the result of a single dependency health check.
type DependencyStatus struct {
	Status    string
	Message   string
	Duration  int64
	Timestamp time.Time
}

const (
	statusHealthy  = "healthy"
	statusDegraded = "degraded"
	statusError    = "error"

	dependencyCheckTimeout = 3 * time.Second
)

// CheckHealth checks all dependencies and returns a structured health response.
func (s *HealthService) CheckHealth(ctx context.Context) HealthStatus {
	deps := make(map[string]DependencyStatus, 2)

	deps["postgresql"] = s.checkDependency(ctx, "postgresql", s.dbChecker)
	deps["valkey"] = s.checkDependency(ctx, "valkey", s.cacheChecker)

	overall := statusHealthy
	failCount := 0
	for _, dep := range deps {
		if dep.Status != statusHealthy {
			failCount++
		}
	}
	switch failCount {
	case 1:
		overall = statusDegraded
	case 2:
		overall = statusError
	}

	return HealthStatus{
		Status:       overall,
		ServiceName:  s.serviceName,
		Version:      s.version,
		Commit:       s.commit,
		BuildTime:    s.buildTime,
		GoVersion:    runtime.Version(),
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Timestamp:    time.Now().UTC(),
		Dependencies: deps,
	}
}

func (s *HealthService) checkDependency(ctx context.Context, name string, checker HealthChecker) DependencyStatus {
	checkCtx, cancel := context.WithTimeout(ctx, dependencyCheckTimeout)
	defer cancel()

	start := time.Now()
	err := checker.Ping(checkCtx)
	duration := time.Since(start)

	check := DependencyStatus{
		Duration:  duration.Milliseconds(),
		Timestamp: time.Now().UTC(),
	}

	if err != nil {
		check.Status = statusError
		check.Message = err.Error()
		s.logger.Warn("dependency health check failed", "dependency", name, "error", err)
	} else {
		check.Status = statusHealthy
	}

	return check
}
