package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestConfigViolationsIncrement(t *testing.T) {
	ConfigViolations.Reset()

	ConfigViolations.WithLabelValues("nginx-rule", "default", "my-pod", "nginx").Inc()
	ConfigViolations.WithLabelValues("nginx-rule", "default", "my-pod", "nginx").Inc()
	ConfigViolations.WithLabelValues("sidecar-rule", "kube-system", "other-pod", "sidecar").Inc()

	if got := testutil.ToFloat64(ConfigViolations.WithLabelValues("nginx-rule", "default", "my-pod", "nginx")); got != 2 {
		t.Fatalf("expected 2 violations for nginx-rule/default/my-pod/nginx, got %v", got)
	}

	if got := testutil.ToFloat64(ConfigViolations.WithLabelValues("sidecar-rule", "kube-system", "other-pod", "sidecar")); got != 1 {
		t.Fatalf("expected 1 violation for sidecar-rule/kube-system/other-pod/sidecar, got %v", got)
	}
}
