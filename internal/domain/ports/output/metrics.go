package output

import "time"

type MetricsProvider interface {
	IncrementGRPCRequests(method, status string)
	RecordGRPCRequestDuration(method, status string, duration time.Duration)

	IncrementDatabaseQueries(queryType string, success bool)
	RecordDatabaseQueryDuration(queryType string, duration time.Duration)

	IncrementAuthOperations(operation string, success bool)
	IncrementTokenOperations(operation string, success bool)
	SetActiveConnections(count int)

	SetServiceHealth(healthy bool)
}
