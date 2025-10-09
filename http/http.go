package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/beemflow/beemflow/auth"
	"github.com/beemflow/beemflow/config"
	"github.com/beemflow/beemflow/constants"
	api "github.com/beemflow/beemflow/core"
	"github.com/beemflow/beemflow/event"
	"github.com/beemflow/beemflow/registry"
	"github.com/beemflow/beemflow/utils"
	"github.com/beemflow/beemflow/webhook"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	otelhttp "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "beemflow_http_requests_total",
			Help: "Total number of HTTP requests received.",
		},
		[]string{"handler", "method", "code"},
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "beemflow_http_request_duration_seconds",
			Help:    "Duration of HTTP requests.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"handler", "method"},
	)
)

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
}

// StartServer starts the HTTP server with minimal setup - all the heavy lifting
// is now done by the unified operations system
// NewHandler creates the HTTP handler with all routes configured.
// This is useful for testing without starting a real server.
func NewHandler(cfg *config.Config) (http.Handler, func(), error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("config cannot be nil")
	}

	// Initialize tracing
	initTracerFromConfig(cfg)

	// Create HTTP mux
	mux := http.NewServeMux()

	// Serve static files from ./static/ directory under /static/*
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Register system endpoints (health, spec) that don't follow the operation pattern
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"status":"healthy"}`)); err != nil {
			utils.Error("Failed to write health check response: %v", err)
		}
	})

	// Initialize all application dependencies
	deps, err := api.InitializeEngine(cfg)
	if err != nil {
		return nil, nil, err
	}

	// Initialize session store and template renderer
	sessionStore := NewSessionStore()
	templateRenderer := NewTemplateRenderer(".")

	// Load OAuth templates
	if err := templateRenderer.LoadOAuthTemplates(); err != nil {
		utils.Error("Failed to load OAuth templates: %v", err)
		if sessionStore != nil {
			sessionStore.Close()
		}
		if deps.Cleanup != nil {
			deps.Cleanup()
		}
		return nil, nil, err
	}

	// Setup OAuth client routes (always enabled for connecting to external services)
	baseURL := auth.GetOAuthIssuerURL(cfg)
	RegisterWebOAuthRoutes(mux, deps.Storage, registry.NewDefaultRegistry(), baseURL, sessionStore, templateRenderer)

	// Setup OAuth server endpoints only if OAuth server is enabled
	var oauthServer *auth.OAuthServer
	if cfg.OAuth != nil && cfg.OAuth.Enabled {
		oauthServer = auth.SetupOAuthServer(cfg, deps.Storage)
		if err := auth.SetupOAuthHandlers(mux, cfg, deps.Storage); err != nil {
			if sessionStore != nil {
				sessionStore.Close()
			}
			if deps.Cleanup != nil {
				deps.Cleanup()
			}
			return nil, nil, err
		}
	}

	// Generate and register all operation handlers
	api.GenerateHTTPHandlers(mux)

	// Setup webhook endpoints (dependencies injected)
	webhookManager, err := setupWebhookRoutes(mux, deps.EventBus, deps.Registry)
	if err != nil {
		utils.Warn("Failed to setup webhook routes: %v", err)
	}

	// Setup MCP routes (auth required only when OAuth server is running)
	mcpRequireAuth := oauthServer != nil
	setupMCPRoutes(mux, deps.Storage, oauthServer, mcpRequireAuth)

	// Register metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// Create session middleware
	sessionMiddleware := NewSessionMiddleware(sessionStore)

	// Create wrapped handler with middleware
	wrappedMux := otelhttp.NewHandler(
		requestIDMiddleware(
			sessionMiddleware.Middleware(
				metricsMiddleware("root", mux),
			),
		),
		"http.root",
	)

	// Create combined cleanup function with defensive nil checks
	cleanup := func() {
		var cleanupErrors []error

		if webhookManager != nil {
			if err := webhookManager.Close(); err != nil {
				cleanupErrors = append(cleanupErrors, err)
				utils.Error("Failed to close webhook manager: %v", err)
			}
		}
		if sessionStore != nil {
			sessionStore.Close()
		}
		if deps.Cleanup != nil {
			deps.Cleanup()
		}

		// Log if there were any cleanup errors
		if len(cleanupErrors) > 0 {
			utils.Warn("Encountered %d error(s) during cleanup", len(cleanupErrors))
		}
	}

	return wrappedMux, cleanup, nil
}

func StartServer(cfg *config.Config) error {
	// Create handler
	handler, cleanup, err := NewHandler(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	// Initialize system cron integration for server mode
	if err := setupSystemCron(cfg); err != nil {
		utils.Warn("Failed to setup system cron integration: %v", err)
		utils.Info("You can manually add cron entries or use the /cron endpoint")
	}

	// Ensure cron entries are cleaned up on shutdown
	defer cleanupSystemCron()

	// Determine server address
	addr := getServerAddress(cfg)

	// Start server with graceful shutdown
	return startServerWithGracefulShutdown(addr, handler)
}

// getServerAddress determines the server address from config and environment variables
func getServerAddress(cfg *config.Config) string {
	// Check environment variable first
	if portStr := os.Getenv(constants.EnvHTTPServerPort); portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil {
			host := constants.DefaultServerHost
			if cfg.HTTP != nil && cfg.HTTP.Host != "" {
				host = cfg.HTTP.Host
			}
			return fmt.Sprintf("%s:%d", host, port)
		}
	}

	// Fall back to config file
	if cfg.HTTP != nil && cfg.HTTP.Port != 0 {
		host := cfg.HTTP.Host
		if host == "" {
			host = "0.0.0.0"
		}
		return fmt.Sprintf("%s:%d", host, cfg.HTTP.Port)
	}

	// Default fallback
	return fmt.Sprintf("%s:%d", constants.DefaultServerHost, constants.DefaultHTTPServerPort)
}

// startServerWithGracefulShutdown starts the HTTP server and handles graceful shutdown
func startServerWithGracefulShutdown(addr string, handler http.Handler) error {
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Channel to listen for errors from ListenAndServe
	errChan := make(chan error, 1)
	go func() {
		utils.Info("HTTP server starting on %s", addr)
		errChan <- server.ListenAndServe()
	}()

	// Listen for interrupt signal for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		utils.Info("Received signal %v, shutting down HTTP server...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			utils.Error("HTTP server shutdown error: %v", err)
			return err
		}
		utils.Info("HTTP server shutdown complete.")
		return nil
	case err := <-errChan:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			utils.Error("HTTP server error: %v", err)
			return err
		}
		return nil
	}
}

// initTracerFromConfig sets up OpenTelemetry tracing based on config.
func initTracerFromConfig(cfg *config.Config) {
	var tp *trace.TracerProvider
	serviceName := "beemflow"
	if cfg.Tracing != nil && cfg.Tracing.ServiceName != "" {
		serviceName = cfg.Tracing.ServiceName
	}
	res, _ := resource.New(
		context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
		),
	)
	switch {
	case cfg.Tracing == nil || cfg.Tracing.Exporter == "stdout":
		exp, _ := stdouttrace.New(stdouttrace.WithPrettyPrint())
		tp = trace.NewTracerProvider(
			trace.WithBatcher(exp),
			trace.WithResource(res),
		)
	case cfg.Tracing.Exporter == "otlp":
		endpoint := cfg.Tracing.Endpoint
		if endpoint == "" {
			endpoint = "http://localhost:4318"
		}
		exp, err := otlptracehttp.New(context.Background(), otlptracehttp.WithEndpoint(endpoint), otlptracehttp.WithInsecure())
		if err == nil {
			tp = trace.NewTracerProvider(
				trace.WithBatcher(exp),
				trace.WithResource(res),
			)
		}
	default:
		exp, _ := stdouttrace.New(stdouttrace.WithPrettyPrint())
		tp = trace.NewTracerProvider(
			trace.WithBatcher(exp),
			trace.WithResource(res),
		)
	}
	if tp != nil {
		otel.SetTracerProvider(tp)
	}
}

// requestIDMiddleware generates a request ID for each request and stores it in the context.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-Id")
		if reqID == "" {
			reqID = uuid.New().String()
		}
		ctx := utils.WithRequestID(r.Context(), reqID)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-Id", reqID)
		next.ServeHTTP(w, r)
	})
}

// metricsMiddleware instruments HTTP handlers for Prometheus.
func metricsMiddleware(handlerName string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		duration := time.Since(start).Seconds()
		httpRequestsTotal.WithLabelValues(handlerName, r.Method, fmt.Sprintf("%d", rw.status)).Inc()
		httpRequestDuration.WithLabelValues(handlerName, r.Method).Observe(duration)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// TEST UTILITIES (consolidated from test_utils.go)

// UpdateRunEvent updates the event for a run.
// Used for tests and directly accesses the storage layer.
// setupSystemCron configures system cron entries for workflows
func setupSystemCron(cfg *config.Config) error {
	// Only setup cron in server mode with a configured port
	if cfg.HTTP == nil || cfg.HTTP.Port == 0 {
		return nil
	}

	host := cfg.HTTP.Host
	if host == "" {
		host = "localhost"
	}
	serverURL := fmt.Sprintf("http://%s:%d", host, cfg.HTTP.Port)

	cronSecret := os.Getenv("CRON_SECRET")
	manager := api.NewCronManager(serverURL, cronSecret)
	return manager.SyncCronEntries(context.Background())
}

// cleanupSystemCron removes BeemFlow cron entries on shutdown
func cleanupSystemCron() {
	manager := api.NewCronManager("", "")
	if err := manager.RemoveAllEntries(); err != nil {
		utils.Warn("Failed to cleanup cron entries: %v", err)
	}
}

func UpdateRunEvent(id uuid.UUID, newEvent map[string]any) error {
	// Get storage from config
	cfg, err := api.GetConfig()
	if err != nil {
		return utils.Errorf("failed to load config: %v", err)
	}

	// Get the configured storage using the helper function from api package
	store, err := api.GetStoreFromConfig(cfg)
	if err != nil {
		return err
	}

	// Get the run
	run, err := store.GetRun(context.Background(), id)
	if err != nil {
		return utils.Errorf("run not found")
	}

	// Update the event
	run.Event = newEvent

	// Save the updated run
	return store.SaveRun(context.Background(), run)
}

// setupWebhookRoutes initializes webhook endpoints (dependencies injected)
func setupWebhookRoutes(mux *http.ServeMux, eventBus event.EventBus, registryMgr *registry.RegistryManager) (*webhook.Manager, error) {
	webhookManager := webhook.NewManager(mux, eventBus, registryMgr)

	ctx := context.Background()
	if err := webhookManager.LoadProvidersWithWebhooks(ctx); err != nil {
		webhookManager.Close()
		return nil, fmt.Errorf("failed to load webhook providers: %w", err)
	}

	utils.Info("Webhook routes setup completed")
	return webhookManager, nil
}
