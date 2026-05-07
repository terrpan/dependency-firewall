// servers.go owns HTTP/gRPC server construction, JSON codec wiring, and graceful shutdown.
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/internal/infra/telemetry"
)

type server struct {
	name     string
	start    func() error
	shutdown func(context.Context) error
}

func serve(ctx context.Context, logger *slog.Logger, servers ...server) error {
	runCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, len(servers))
	for i := range servers {
		srv := servers[i]
		go func() {
			err := srv.start()
			if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, grpc.ErrServerStopped) {
				errCh <- nil
				return
			}
			errCh <- fmt.Errorf("%s: %w", srv.name, err)
		}()
	}

	var runErr error
	select {
	case <-runCtx.Done():
		logger.Info("received shutdown signal")
	case err := <-errCh:
		if err != nil {
			runErr = err
			logger.Error("server exited", "error", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	shutdownErrCh := make(chan error, len(servers))
	for i := range servers {
		srv := servers[i]
		if srv.shutdown == nil {
			continue
		}
		wg.Go(func() {
			if err := srv.shutdown(shutdownCtx); err != nil {
				shutdownErrCh <- err
			}
		})
	}
	wg.Wait()
	close(shutdownErrCh)

	for err := range shutdownErrCh {
		if err != nil && runErr == nil {
			runErr = fmt.Errorf("graceful shutdown: %w", err)
		}
	}

	return runErr
}

func newHTTPServer(cfg *config.Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      telemetry.WrapHTTPHandler(handler),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}
}

type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (jsonCodec) Name() string {
	return "json"
}
