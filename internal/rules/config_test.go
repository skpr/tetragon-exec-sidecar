package rules

import (
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func TestRules_MatchProcessExec(t *testing.T) {
	makeProcessExec := func(namespace, container string, labels map[string]string, binary string) *tetragon.ProcessExec {
		return &tetragon.ProcessExec{
			Process: &tetragon.Process{
				Binary: binary,
				Pod: &tetragon.Pod{
					Namespace: namespace,
					PodLabels: labels,
					Container: &tetragon.Container{
						Name: container,
					},
				},
			},
		}
	}

	tests := []struct {
		name   string
		rules  Rules
		pe     *tetragon.ProcessExec
		wantID string
		want   bool
	}{
		{
			name:  "no pod info => false",
			rules: Rules{"catch-all": {}},
			pe: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Binary: "/bin/sh",
				},
			},
			want: false,
		},
		{
			name: "namespace list defined but does not contain pod namespace => false",
			rules: Rules{
				"ns-rule": {Namespaces: []string{"prod"}},
			},
			pe:   makeProcessExec("dev", "c1", map[string]string{"app": "x"}, "/bin/sh"),
			want: false,
		},
		{
			name: "container list defined but does not contain pod container => false",
			rules: Rules{
				"container-rule": {Containers: []string{"allowed"}},
			},
			pe:   makeProcessExec("ns", "other", map[string]string{"app": "x"}, "/bin/sh"),
			want: false,
		},
		{
			name: "labels defined but do not match => false",
			rules: Rules{
				"label-rule": {Labels: map[string]string{"app": "api", "tier": "backend"}},
			},
			pe:   makeProcessExec("ns", "c1", map[string]string{"app": "api", "tier": "frontend"}, "/bin/sh"),
			want: false,
		},
		{
			name: "binary is excluded => false",
			rules: Rules{
				"exclude-rule": {ExcludeBinaries: []string{"/bin/sh"}},
			},
			pe:   makeProcessExec("ns", "c1", map[string]string{"app": "x"}, "/bin/sh"),
			want: false,
		},
		{
			name: "empty criteria rule matches any pod exec => true",
			rules: Rules{
				"catch-all": {},
			},
			pe:     makeProcessExec("any", "any", map[string]string{"k": "v"}, "/usr/bin/curl"),
			wantID: "catch-all",
			want:   true,
		},
		{
			name: "all criteria match => true with correct ID",
			rules: Rules{
				"strict-rule": {
					Namespaces:      []string{"ns-a", "ns-b"},
					Containers:      []string{"c1"},
					Labels:          map[string]string{"app": "api", "tier": "backend"},
					ExcludeBinaries: []string{"/bin/sh"},
				},
			},
			pe:     makeProcessExec("ns-b", "c1", map[string]string{"app": "api", "tier": "backend", "extra": "ok"}, "/usr/bin/curl"),
			wantID: "strict-rule",
			want:   true,
		},
		{
			name: "labels rule requires subset match (pod has extra labels) => true",
			rules: Rules{
				"label-subset": {Labels: map[string]string{"app": "api"}},
			},
			pe:     makeProcessExec("ns", "c1", map[string]string{"app": "api", "tier": "backend"}, "/usr/bin/curl"),
			wantID: "label-subset",
			want:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotID, got := tc.rules.MatchProcessExec(tc.pe)
			if got != tc.want {
				t.Fatalf("MatchProcessExec() matched = %v, want %v", got, tc.want)
			}
			if got && gotID != tc.wantID {
				t.Fatalf("MatchProcessExec() id = %q, want %q", gotID, tc.wantID)
			}
			if !got && gotID != "" {
				t.Fatalf("MatchProcessExec() id = %q, want empty on no match", gotID)
			}
		})
	}
}
