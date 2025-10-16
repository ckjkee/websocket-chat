package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path", "status"},
	)

	WSConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ws_active_connections",
			Help: "Number of active WebSocket connections",
		},
	)

	MessagesBroadcastTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "chat_messages_broadcast_total",
			Help: "Total number of chat messages broadcasted",
		},
	)

	MessageSizeBytes = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "chat_message_size_bytes",
			Help:    "Size of chat messages in bytes",
			Buckets: []float64{64, 256, 1024, 4096, 16384, 65536},
		},
	)

	RedisErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "redis_errors_total",
			Help: "Total number of Redis errors",
		},
	)

	WSUpgradeErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ws_upgrade_errors_total",
			Help: "Total number of WebSocket upgrade errors",
		},
	)

	WSAuthFailuresTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ws_auth_failures_total",
			Help: "Total number of WebSocket authentication failures",
		},
	)

	WSReadErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ws_read_errors_total",
			Help: "Total number of WebSocket read errors",
		},
	)

	WSWriteErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ws_write_errors_total",
			Help: "Total number of WebSocket write errors",
		},
	)

	LoginAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "login_attempts_total",
			Help: "Total number of login attempts",
		},
		[]string{"result"},
	)

	RegisterAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "register_attempts_total",
			Help: "Total number of register attempts",
		},
		[]string{"result"},
	)
)

func ObserveHTTPRequest(method, path string, status int, duration time.Duration) {
	statusLabel := http.StatusText(status)
	if statusLabel == "" {
		statusLabel = "UNKNOWN"
	}
	labels := prometheus.Labels{"method": method, "path": path, "status": statusLabel}
	HTTPRequestsTotal.With(labels).Inc()
	HTTPRequestDuration.With(labels).Observe(duration.Seconds())
}

func IncWSConnections()        { WSConnections.Inc() }
func DecWSConnections()        { WSConnections.Dec() }
func IncMessagesBroadcast()    { MessagesBroadcastTotal.Inc() }
func IncRedisError()           { RedisErrorsTotal.Inc() }
func ObserveMessageSize(n int) { MessageSizeBytes.Observe(float64(n)) }
func IncLoginAttempt(success bool) {
	if success {
		LoginAttemptsTotal.WithLabelValues("success").Inc()
	} else {
		LoginAttemptsTotal.WithLabelValues("failure").Inc()
	}
}
func IncRegisterAttempt(success bool) {
	if success {
		RegisterAttemptsTotal.WithLabelValues("success").Inc()
	} else {
		RegisterAttemptsTotal.WithLabelValues("failure").Inc()
	}
}

func IncWSUpgradeError() { WSUpgradeErrorsTotal.Inc() }
func IncWSAuthFailure()  { WSAuthFailuresTotal.Inc() }
func IncWSReadError()    { WSReadErrorsTotal.Inc() }
func IncWSWriteError()   { WSWriteErrorsTotal.Inc() }
