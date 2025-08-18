package prometheus

import (
	"time"

	ports "pinstack-auth-service/internal/domain/ports/output"
)

// PrometheusMetricsProvider implements the MetricsProvider interface for Prometheus
type PrometheusMetricsProvider struct{}

// NewPrometheusMetricsProvider creates a new Prometheus metrics provider
func NewPrometheusMetricsProvider() ports.MetricsProvider {
	return &PrometheusMetricsProvider{}
}

// IncrementGRPCRequests increments the gRPC requests counter
func (p *PrometheusMetricsProvider) IncrementGRPCRequests(method, status string) {
	grpcRequestsTotal.WithLabelValues(method, status).Inc()
}

// RecordGRPCRequestDuration records the duration of a gRPC request
func (p *PrometheusMetricsProvider) RecordGRPCRequestDuration(method, status string, duration time.Duration) {
	grpcRequestDuration.WithLabelValues(method, status).Observe(duration.Seconds())
}

// IncrementDatabaseQueries increments the database queries counter
func (p *PrometheusMetricsProvider) IncrementDatabaseQueries(queryType string, success bool) {
	status := "failure"
	if success {
		status = "success"
	}
	databaseQueriesTotal.WithLabelValues(queryType, status).Inc()
}

// RecordDatabaseQueryDuration records the duration of a database query
func (p *PrometheusMetricsProvider) RecordDatabaseQueryDuration(queryType string, duration time.Duration) {
	databaseQueryDuration.WithLabelValues(queryType).Observe(duration.Seconds())
}

// IncrementAuthOperations increments the auth operations counter
func (p *PrometheusMetricsProvider) IncrementAuthOperations(operation string, success bool) {
	status := "failure"
	if success {
		status = "success"
	}
	authOperationsTotal.WithLabelValues(operation, status).Inc()
}

// IncrementTokenOperations increments the token operations counter
func (p *PrometheusMetricsProvider) IncrementTokenOperations(operation string, success bool) {
	status := "failure"
	if success {
		status = "success"
	}
	tokenOperationsTotal.WithLabelValues(operation, status).Inc()
}

// SetActiveConnections sets the number of active connections
func (p *PrometheusMetricsProvider) SetActiveConnections(count int) {
	activeConnections.Set(float64(count))
}

// SetServiceHealth sets the service health status
func (p *PrometheusMetricsProvider) SetServiceHealth(healthy bool) {
	if healthy {
		serviceHealth.Set(1)
	} else {
		serviceHealth.Set(0)
	}
}
