package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// gRPC metrics
	grpcRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_service_grpc_requests_total",
			Help: "Total number of gRPC requests",
		},
		[]string{"method", "status"},
	)

	grpcRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "auth_service_grpc_request_duration_seconds",
			Help:    "Duration of gRPC requests",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "status"},
	)

	// Database metrics
	databaseQueriesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_service_database_queries_total",
			Help: "Total number of database queries",
		},
		[]string{"query_type", "status"},
	)

	databaseQueryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "auth_service_database_query_duration_seconds",
			Help:    "Duration of database queries",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"query_type"},
	)

	// Auth operations metrics
	authOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_service_auth_operations_total",
			Help: "Total number of auth operations",
		},
		[]string{"operation", "status"},
	)

	tokenOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_service_token_operations_total",
			Help: "Total number of token operations",
		},
		[]string{"operation", "status"},
	)

	// Connection metrics
	activeConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "auth_service_active_connections",
			Help: "Number of active connections",
		},
	)

	// Service health
	serviceHealth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "auth_service_health",
			Help: "Service health status (1 = healthy, 0 = unhealthy)",
		},
	)
)
