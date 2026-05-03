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
	bundleStatus ComponentStatusChecker
	proxyChecker ComponentStatusChecker
	proxyStatus  *ComponentStatus
	logger       *slog.Logger
}

// HealthOption customizes HealthService behavior.
type HealthOption func(*HealthService)

// ComponentStatusChecker reports the status of a first-class runtime component.
type ComponentStatusChecker interface {
	CheckStatus(ctx context.Context) ComponentStatus
}

// WithProxyStatus includes proxy runtime status in health responses.
func WithProxyStatus(status, message string) HealthOption {
	return func(s *HealthService) {
		s.proxyStatus = &ComponentStatus{
			Status:  status,
			Message: message,
		}
	}
}

// WithProxyStatusChecker includes dynamically checked proxy status in health responses.
func WithProxyStatusChecker(checker ComponentStatusChecker) HealthOption {
	return func(s *HealthService) {
		s.proxyChecker = checker
	}
}

// WithBundleStatusChecker includes bundle runtime status in health responses.
func WithBundleStatusChecker(checker ComponentStatusChecker) HealthOption {
	return func(s *HealthService) {
		s.bundleStatus = checker
	}
}

// NewHealthService creates a new HealthService.
func NewHealthService(
	serviceName, version, commit, buildTime string,
	dbChecker, cacheChecker HealthChecker,
	logger *slog.Logger,
	opts ...HealthOption,
) *HealthService {
	svc := &HealthService{
		serviceName:  serviceName,
		version:      version,
		commit:       commit,
		buildTime:    buildTime,
		dbChecker:    dbChecker,
		cacheChecker: cacheChecker,
		logger:       logger,
	}

	for _, opt := range opts {
		opt(svc)
	}

	return svc
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
	Bundle       *ComponentStatus
	Proxy        *ComponentStatus
}

// DependencyStatus holds the result of a single dependency health check.
type DependencyStatus struct {
	Status    string
	Message   string
	Duration  int64
	Timestamp time.Time
}

// ComponentStatus holds the status of a first-class runtime component.
type ComponentStatus struct {
	Status    string
	Message   string
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
	now := time.Now().UTC()

	if s.dbChecker != nil {
		deps["postgresql"] = s.checkDependency(ctx, "postgresql", s.dbChecker)
	}
	if s.cacheChecker != nil {
		deps["valkey"] = s.checkDependency(ctx, "valkey", s.cacheChecker)
	}

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

	status := HealthStatus{
		Status:       overall,
		ServiceName:  s.serviceName,
		Version:      s.version,
		Commit:       s.commit,
		BuildTime:    s.buildTime,
		GoVersion:    runtime.Version(),
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Timestamp:    now,
		Dependencies: deps,
	}

	switch {
	case s.proxyChecker != nil:
		component := s.proxyChecker.CheckStatus(ctx)
		if component.Timestamp.IsZero() {
			component.Timestamp = now
		}
		status.Proxy = &component
	case s.proxyStatus != nil:
		status.Proxy = &ComponentStatus{
			Status:    s.proxyStatus.Status,
			Message:   s.proxyStatus.Message,
			Timestamp: now,
		}
	}
	if s.bundleStatus != nil {
		component := s.bundleStatus.CheckStatus(ctx)
		if component.Timestamp.IsZero() {
			component.Timestamp = now
		}
		status.Bundle = &component
	}

	return status
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
