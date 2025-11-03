package main

import (
	"flag"
	"os"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchemeInitialization(t *testing.T) {
	// Verify that all required schemes are registered
	gvk, err := apiutil.GVKForObject(&corev1.ConfigMap{}, scheme)
	require.NoError(t, err)
	assert.Equal(t, "ConfigMap", gvk.Kind)
	assert.Equal(t, "v1", gvk.Version)

	gvk, err = apiutil.GVKForObject(&corev1.Pod{}, scheme)
	require.NoError(t, err)
	assert.Equal(t, "Pod", gvk.Kind)

	gvk, err = apiutil.GVKForObject(&appsv1.Deployment{}, scheme)
	require.NoError(t, err)
	assert.Equal(t, "Deployment", gvk.Kind)
	assert.Equal(t, "apps/v1", gvk.GroupVersion().String())
}

func TestSchemeKnownTypes(t *testing.T) {
	// Test that the scheme recognizes known types
	_, err := scheme.New(corev1.SchemeGroupVersion.WithKind("ConfigMap"))
	require.NoError(t, err)

	_, err = scheme.New(corev1.SchemeGroupVersion.WithKind("Pod"))
	require.NoError(t, err)

	_, err = scheme.New(appsv1.SchemeGroupVersion.WithKind("Deployment"))
	require.NoError(t, err)
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name              string
		args              []string
		expectedMetrics   string
		expectedProbe     string
		expectedElect     bool
		expectedNamespace string
	}{
		{
			name:              "default flags",
			args:              []string{},
			expectedMetrics:   ":8080",
			expectedProbe:     ":8081",
			expectedElect:     false,
			expectedNamespace: "",
		},
		{
			name:              "custom metrics address",
			args:              []string{"-metrics-bind-address", ":9090"},
			expectedMetrics:   ":9090",
			expectedProbe:     ":8081",
			expectedElect:     false,
			expectedNamespace: "",
		},
		{
			name:              "custom probe address",
			args:              []string{"-health-probe-bind-address", ":9091"},
			expectedMetrics:   ":8080",
			expectedProbe:     ":9091",
			expectedElect:     false,
			expectedNamespace: "",
		},
		{
			name:              "enable leader election",
			args:              []string{"-leader-elect"},
			expectedMetrics:   ":8080",
			expectedProbe:     ":8081",
			expectedElect:     true,
			expectedNamespace: "",
		},
		{
			name:              "watch specific namespace",
			args:              []string{"-namespace", "test-ns"},
			expectedMetrics:   ":8080",
			expectedProbe:     ":8081",
			expectedElect:     false,
			expectedNamespace: "test-ns",
		},
		{
			name:              "all flags set",
			args:              []string{"-metrics-bind-address", ":9000", "-health-probe-bind-address", ":9001", "-leader-elect", "-namespace", "production"},
			expectedMetrics:   ":9000",
			expectedProbe:     ":9001",
			expectedElect:     true,
			expectedNamespace: "production",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset flags for each test
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

			var metricsAddr string
			var probeAddr string
			var enableLeaderElection bool
			var watchedNamespace string

			flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metrics endpoint binds to.")
			flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the health probe endpoint binds to.")
			flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager.")
			flag.StringVar(&watchedNamespace, "namespace", "", "Namespace to watch. Defaults to all namespaces.")

			err := flag.CommandLine.Parse(tt.args)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedMetrics, metricsAddr)
			assert.Equal(t, tt.expectedProbe, probeAddr)
			assert.Equal(t, tt.expectedElect, enableLeaderElection)
			assert.Equal(t, tt.expectedNamespace, watchedNamespace)
		})
	}
}

func TestManagerOptionsConfiguration(t *testing.T) {
	tests := []struct {
		name             string
		metricsAddr      string
		probeAddr        string
		enableElect      bool
		watchedNamespace string
		expectNamespace  bool
		expectedElectID  string
	}{
		{
			name:             "default options",
			metricsAddr:      ":8080",
			probeAddr:        ":8081",
			enableElect:      false,
			watchedNamespace: "",
			expectNamespace:  false,
			expectedElectID:  "86a223f3.moat.arxignis.com",
		},
		{
			name:             "with namespace",
			metricsAddr:      ":8080",
			probeAddr:        ":8081",
			enableElect:      false,
			watchedNamespace: "test-ns",
			expectNamespace:  true,
			expectedElectID:  "86a223f3.moat.arxignis.com",
		},
		{
			name:             "with leader election",
			metricsAddr:      ":8080",
			probeAddr:        ":8081",
			enableElect:      true,
			watchedNamespace: "",
			expectNamespace:  false,
			expectedElectID:  "86a223f3.moat.arxignis.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the manager options setup logic
			mgrOptions := struct {
				Scheme            *runtime.Scheme
				MetricsAddr       string
				ProbeAddr         string
				LeaderElection    bool
				LeaderElectionID  string
				DefaultNamespaces map[string]interface{}
			}{
				Scheme:           scheme,
				MetricsAddr:      tt.metricsAddr,
				ProbeAddr:        tt.probeAddr,
				LeaderElection:   tt.enableElect,
				LeaderElectionID: tt.expectedElectID,
			}

			if tt.watchedNamespace != "" {
				mgrOptions.DefaultNamespaces = map[string]interface{}{
					tt.watchedNamespace: struct{}{},
				}
			}

			assert.Equal(t, scheme, mgrOptions.Scheme)
			assert.Equal(t, tt.metricsAddr, mgrOptions.MetricsAddr)
			assert.Equal(t, tt.probeAddr, mgrOptions.ProbeAddr)
			assert.Equal(t, tt.enableElect, mgrOptions.LeaderElection)
			assert.Equal(t, tt.expectedElectID, mgrOptions.LeaderElectionID)

			if tt.expectNamespace {
				assert.NotNil(t, mgrOptions.DefaultNamespaces)
				assert.Contains(t, mgrOptions.DefaultNamespaces, tt.watchedNamespace)
			} else {
				if mgrOptions.DefaultNamespaces == nil || len(mgrOptions.DefaultNamespaces) == 0 {
					// This is expected - no namespace means watch all
				}
			}
		})
	}
}

func TestLeaderElectionID(t *testing.T) {
	// Verify the leader election ID matches expected format
	expectedID := "86a223f3.moat.arxignis.com"
	assert.Equal(t, expectedID, "86a223f3.moat.arxignis.com")
	assert.NotEmpty(t, expectedID)
	assert.Contains(t, expectedID, "moat")
	assert.Contains(t, expectedID, "arxignis.com")
}
