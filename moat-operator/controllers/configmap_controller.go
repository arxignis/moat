package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	moatLabelKey       = "app.kubernetes.io/name"
	moatLabelValue     = "moat"
	configHashAnnotKey = "moat.arxignis.com/config-hash"
)

// ConfigMapReconciler watches Moat config ConfigMaps and forces a rollout on the Deployment when the config changes.
type ConfigMapReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile reacts to ConfigMap updates by updating the pod template annotation on Moat Deployments.
func (r *ConfigMapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("configmap", req.NamespacedName)

	var cfg corev1.ConfigMap
	if err := r.Get(ctx, req.NamespacedName, &cfg); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("ConfigMap was deleted, nothing to do")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if cfg.Labels[moatLabelKey] != moatLabelValue {
		logger.V(1).Info("ConfigMap does not belong to Moat, skipping")
		return ctrl.Result{}, nil
	}

	hash := hashConfigMapContent(&cfg)
	if hash == "" {
		logger.Info("ConfigMap has no data entries, skipping rollout")
		return ctrl.Result{}, nil
	}

	deployments := &appsv1.DeploymentList{}
	if err := r.List(
		ctx,
		deployments,
		client.InNamespace(req.Namespace),
		client.MatchingLabels{moatLabelKey: moatLabelValue},
	); err != nil {
		return ctrl.Result{}, err
	}

	for i := range deployments.Items {
		deploy := &deployments.Items[i]
		logger := logger.WithValues("deployment", deploy.Name)

		original := deploy.DeepCopy()
		if deploy.Spec.Template.Annotations == nil {
			deploy.Spec.Template.Annotations = map[string]string{}
		}

		if existing := deploy.Spec.Template.Annotations[configHashAnnotKey]; existing == hash {
			logger.V(1).Info("Deployment already up to date with config hash")
			continue
		}

		deploy.Spec.Template.Annotations[configHashAnnotKey] = hash
		if err := r.Patch(ctx, deploy, client.MergeFrom(original)); err != nil {
			logger.Error(err, "failed to update deployment with new config hash")
			return ctrl.Result{}, err
		}
		logger.Info("Updated deployment pod template annotation to trigger restart", "configHash", hash)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager configures the controller to watch ConfigMaps with the Moat label.
func (r *ConfigMapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(
			&corev1.ConfigMap{},
			builder.WithPredicates(predicate.NewPredicateFuncs(isMoatObject)),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}

func isMoatObject(obj client.Object) bool {
	if obj == nil {
		return false
	}
	return obj.GetLabels()[moatLabelKey] == moatLabelValue
}

func hashConfigMapContent(cfg *corev1.ConfigMap) string {
	if len(cfg.Data) == 0 && len(cfg.BinaryData) == 0 {
		return ""
	}

	keys := make([]string, 0, len(cfg.Data)+len(cfg.BinaryData))
	for k := range cfg.Data {
		keys = append(keys, "s:"+k)
	}
	for k := range cfg.BinaryData {
		keys = append(keys, "b:"+k)
	}
	sort.Strings(keys)

	hasher := sha256.New()
	for _, k := range keys {
		switch {
		case len(k) > 2 && k[0:2] == "s:":
			key := k[2:]
			hasher.Write([]byte("s"))
			hasher.Write([]byte(key))
			hasher.Write([]byte{0})
			hasher.Write([]byte(cfg.Data[key]))
		case len(k) > 2 && k[0:2] == "b:":
			key := k[2:]
			hasher.Write([]byte("b"))
			hasher.Write([]byte(key))
			hasher.Write([]byte{0})
			hasher.Write(cfg.BinaryData[key])
		}
		hasher.Write([]byte{0})
	}
	return hex.EncodeToString(hasher.Sum(nil))
}
