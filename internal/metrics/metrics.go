package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace = "tetragon_exec_sidecar"
)

var ConfigViolations = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "config_violations_total",
		Help:      "Total number of process exec events that matched a config rule.",
	},
	[]string{"rule_id", "pod_namespace", "pod_name", "container_name"},
)

func init() {
	prometheus.MustRegister(ConfigViolations)
}
