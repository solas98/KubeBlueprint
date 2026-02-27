package generator

import (
  "fmt"
  "strings"
  "strconv"

  "k8s-blueprint/internal/models"
)

// GenerateKustomize returns all files for a Kustomize project
func GenerateKustomize(req models.BlueprintRequest) []models.GeneratedFile {
	name := req.AppName
	img := req.Image
  // Port is provided as a string; parse into int for template rendering
  port := 8080
  if req.Port != "" {
    if p, err := strconv.Atoi(req.Port); err == nil {
      port = p
    }
  }
	res := toSet(req.Resources)
	sec := req.Security

	imgParts := strings.SplitN(img, ":", 2)
	imgRepo := imgParts[0]
	imgTag := "latest"
	if len(imgParts) == 2 {
		imgTag = imgParts[1]
	}

	var files []models.GeneratedFile
	add := func(path, content string) {
		files = append(files, models.GeneratedFile{Path: path, Content: content})
	}

	// ── base ─────────────────────────────────────────────────────────
	baseResources := buildBaseResourceList(res, req)
	add("base/kustomization.yaml", kustomBaseKustomization(name, imgRepo, imgTag, baseResources))
  add("base/deployment.yaml", kustomDeployment(name, img, port, sec, res))

	if res["service"] {
		add("base/service.yaml", kustomService(name, port))
	}
	if res["serviceaccount"] {
		add("base/serviceaccount.yaml", kustomServiceAccount(name, req.Secrets))
	}
	if res["configmap"] {
		add("base/configmap.yaml", kustomConfigMap(name, port))
	}
	if res["networkpolicy"] && sec.NetPolicy {
		add("base/networkpolicy.yaml", kustomNetworkPolicy(name, port))
	}
	if res["rbac"] {
		add("base/rbac.yaml", kustomRBAC(name))
	}
	if res["hpa"] && !req.Keda.Enabled {
		add("base/hpa.yaml", kustomHPA(name))
	}
	if res["pvc"] {
		add("base/pvc.yaml", kustomPVC(name))
	}
	if res["pdb"] {
		add("base/pdb.yaml", kustomPDB(name))
	}
	if res["vpa"] {
		add("base/vpa.yaml", kustomVPA(name))
	}
	if res["cronjob"] {
		add("base/cronjob.yaml", kustomCronJob(name, img, sec))
	}
	if res["secret"] {
		if req.Secrets.Provider == "external-secrets" {
			add("base/externalsecret.yaml", kustomExternalSecret(name, req.Secrets))
			add("base/secretstore.yaml", kustomSecretStore(name, req.Secrets))
		} else if req.Secrets.Provider == "vault" {
			add("base/vault-secret.yaml", kustomVaultSecret(name, req.Secrets))
			add("base/vault-auth.yaml", kustomVaultAuth(name, req.Secrets))
		} else {
			add("base/secret.yaml", kustomSecretPlaceholder(name))
		}
	}
	if req.Keda.Enabled {
		add("base/keda-scaledobject.yaml", kustomKedaScaledObject(name, req.Keda))
		if req.Keda.Trigger == "kafka" || req.Keda.Trigger == "rabbitmq" || req.Keda.Trigger == "redis" {
			add("base/keda-auth.yaml", kustomKedaTriggerAuth(name, req.Keda))
		}
	}
	if req.Istio.Enabled {
		add("base/virtualservice.yaml", kustomVirtualService(name, req.Istio))
		if req.Istio.DestinationRule {
			add("base/destinationrule.yaml", kustomDestinationRule(name))
		}
		if req.Istio.EnvoyFilter {
			add("base/envoyfilter.yaml", kustomEnvoyFilter(name))
		}
		if req.Istio.AuthorizationPolicy {
			add("base/authorizationpolicy.yaml", kustomAuthorizationPolicy(name, req.Istio))
		}
	}

  // ── overlays (only generate overlays for selected envs) ───────────
  envSet := toSet(req.Envs)

  // dev
  if envSet["dev"] {
    add("overlays/dev/kustomization.yaml", kustomOverlayKustomization(name, imgRepo, "latest", "dev", res, sec, req.Keda))
    add("overlays/dev/patches/deployment-patch.yaml", kustomDevDeploymentPatch(name))
    if res["ingress"] {
      add("overlays/dev/patches/ingress.yaml", kustomDevIngress(name))
    }
    if res["configmap"] {
      add("overlays/dev/patches/configmap-patch.yaml", kustomDevConfigMap(name))
    }
    if res["networkpolicy"] && sec.NetPolicy {
      add("overlays/dev/patches/networkpolicy-patch.yaml", kustomDevNetworkPolicy(name))
    }
    if res["hpa"] && !req.Keda.Enabled {
      add("overlays/dev/patches/hpa-patch.yaml", kustomDevHPAPatch(name))
    }
  }

  // staging
  if envSet["staging"] {
    add("overlays/staging/kustomization.yaml", kustomOverlayKustomization(name, imgRepo, "staging", "staging", res, sec, req.Keda))
    add("overlays/staging/patches/deployment-patch.yaml", kustomStagingDeploymentPatch(name))
    if res["ingress"] {
      add("overlays/staging/patches/ingress.yaml", kustomStagingIngress(name))
    }
    if res["configmap"] {
      add("overlays/staging/patches/configmap-patch.yaml", kustomStagingConfigMap(name))
    }
    if res["hpa"] && !req.Keda.Enabled {
      add("overlays/staging/patches/hpa-patch.yaml", kustomStagingHPAPatch(name))
    }
  }

  // test
  if envSet["test"] {
    add("overlays/test/kustomization.yaml", kustomOverlayKustomization(name, imgRepo, "test", "test", res, sec, req.Keda))
    add("overlays/test/patches/deployment-patch.yaml", kustomTestDeploymentPatch(name))
    if res["ingress"] {
      add("overlays/test/patches/ingress.yaml", kustomStagingIngress(name))
    }
    if res["configmap"] {
      add("overlays/test/patches/configmap-patch.yaml", kustomStagingConfigMap(name))
    }
    if res["hpa"] && !req.Keda.Enabled {
      add("overlays/test/patches/hpa-patch.yaml", kustomTestHPAPatch(name))
    }
  }

  // prod
  if envSet["prod"] {
    add("overlays/prod/kustomization.yaml", kustomOverlayKustomization(name, imgRepo, "1.0.0", "prod", res, sec, req.Keda))
    add("overlays/prod/patches/deployment-patch.yaml", kustomProdDeploymentPatch(name))
    if res["ingress"] {
      add("overlays/prod/patches/ingress.yaml", kustomProdIngress(name))
    }
    if res["hpa"] && !req.Keda.Enabled {
      add("overlays/prod/patches/hpa-patch.yaml", kustomProdHPAPatch(name))
    }
    if res["pdb"] {
      add("overlays/prod/patches/pdb-patch.yaml", kustomProdPDBPatch(name))
    }
    if res["configmap"] {
      add("overlays/prod/patches/configmap-patch.yaml", kustomProdConfigMap(name))
    }
  }

	return files
}

func buildBaseResourceList(res map[string]bool, req models.BlueprintRequest) []string {
	all := []string{"deployment.yaml"}
	if res["service"] {
		all = append(all, "service.yaml")
	}
	if res["serviceaccount"] {
		all = append(all, "serviceaccount.yaml")
	}
	if res["configmap"] {
		all = append(all, "configmap.yaml")
	}
	if res["networkpolicy"] && req.Security.NetPolicy {
		all = append(all, "networkpolicy.yaml")
	}
	if res["rbac"] {
		all = append(all, "rbac.yaml")
	}
	if res["hpa"] && !req.Keda.Enabled {
		all = append(all, "hpa.yaml")
	}
	if res["pvc"] {
		all = append(all, "pvc.yaml")
	}
	if res["pdb"] {
		all = append(all, "pdb.yaml")
	}
	if res["vpa"] {
		all = append(all, "vpa.yaml")
	}
	if res["cronjob"] {
		all = append(all, "cronjob.yaml")
	}
	if res["secret"] {
		if req.Secrets.Provider == "external-secrets" {
			all = append(all, "externalsecret.yaml", "secretstore.yaml")
		} else if req.Secrets.Provider == "vault" {
			all = append(all, "vault-secret.yaml", "vault-auth.yaml")
		}
	}
	if req.Keda.Enabled {
		all = append(all, "keda-scaledobject.yaml")
		if req.Keda.Trigger == "kafka" || req.Keda.Trigger == "rabbitmq" || req.Keda.Trigger == "redis" {
			all = append(all, "keda-auth.yaml")
		}
	}
	return all
}

// ─────────────────────────────────────────────
// base/kustomization.yaml
// ─────────────────────────────────────────────
func kustomBaseKustomization(name, imgRepo, imgTag string, resources []string) string {
	resourceLines := make([]string, len(resources))
	for i, r := range resources {
		resourceLines[i] = "  - " + r
	}
	return fmt.Sprintf(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

# Namespace is set per-overlay; base has no namespace
# namespace: %s

labels:
  - pairs:
      app.kubernetes.io/name: %s
      app.kubernetes.io/managed-by: kustomize
      app.kubernetes.io/part-of: %s

resources:
%s

images:
  - name: %s
    newTag: "%s"
`, name, name, name, strings.Join(resourceLines, "\n"), imgRepo, imgTag)
}

// ─────────────────────────────────────────────
// base/deployment.yaml
// ─────────────────────────────────────────────
func kustomDeployment(name, image string, port int, sec models.Security, res map[string]bool) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`# Deployment — %s
# K8s 1.29–1.35+ best practices
# Pod Security Standards: Restricted profile
apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/component: server
spec:
  replicas: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: %s
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  revisionHistoryLimit: 3
  progressDeadlineSeconds: 600
  template:
    metadata:
      labels:
        app.kubernetes.io/name: %s
        app.kubernetes.io/component: server
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "%d"
    spec:
`, name, name, name, name, name, port))

    if res["serviceaccount"] {
        b.WriteString(fmt.Sprintf(`      serviceAccountName: %s
`, name))
    }

    b.WriteString(`      automountServiceAccountToken: false
      terminationGracePeriodSeconds: 60
      securityContext:
`)

	if sec.NonRoot {
		b.WriteString(`        runAsNonRoot: true
        runAsUser: 65534
        runAsGroup: 65534
        fsGroup: 65534
        fsGroupChangePolicy: OnRootMismatch
`)
	}
	if sec.Seccomp {
		b.WriteString(`        seccompProfile:
          type: RuntimeDefault
`)
	}

	b.WriteString(fmt.Sprintf(`      # Spread across availability zones
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: topology.kubernetes.io/zone
          whenUnsatisfiable: DoNotSchedule
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: %s
          minDomains: 3
      # Prefer different nodes for each replica
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchExpressions:
                  - key: app.kubernetes.io/name
                    operator: In
                    values:
                      - %s
              topologyKey: kubernetes.io/hostname
      containers:
        - name: %s
          image: %s
          imagePullPolicy: IfNotPresent
          securityContext:
`, name, name, name, image))

	if sec.ReadOnly {
		b.WriteString(`            readOnlyRootFilesystem: true
`)
	}
	if sec.NonRoot {
		b.WriteString(`            runAsNonRoot: true
            runAsUser: 65534
`)
	}
	if sec.DropCaps {
		b.WriteString(`            capabilities:
              drop:
                - ALL
`)
	}
	if sec.NoPrivEsc {
		b.WriteString(`            allowPrivilegeEscalation: false
`)
	}
	if sec.Seccomp {
		b.WriteString(`            seccompProfile:
              type: RuntimeDefault
`)
	}

	b.WriteString(fmt.Sprintf(`          ports:
            - name: http
              containerPort: %d
              protocol: TCP
`, port))

    // Build envFrom block based on selected resources
    if res["configmap"] || res["secret"] {
        b.WriteString(`          envFrom:
`)
        if res["configmap"] {
            b.WriteString(fmt.Sprintf(`            - configMapRef:
                name: %s-config
`, name))
        }
        if res["secret"] {
            b.WriteString(fmt.Sprintf(`            - secretRef:
                name: %s-secret
`, name))
        }
    }

	b.WriteString(fmt.Sprintf(`          livenessProbe:
            httpGet:
              path: /healthz
              port: %d
            initialDelaySeconds: 15
            periodSeconds: 20
            timeoutSeconds: 5
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /readyz
              port: %d
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3
          startupProbe:
            httpGet:
              path: /healthz
              port: %d
            failureThreshold: 30
            periodSeconds: 10
          resources:
            limits:
              cpu: 500m
              memory: 256Mi

            requests:
              cpu: 100m
              memory: 128Mi

`, port, port, port))

    // Only include volume mounts and volumes when PVCs are requested
    if res["pvc"] {
        b.WriteString(fmt.Sprintf(`          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: varrun
              mountPath: /var/run
            - name: data
              mountPath: /data
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 100Mi
        - name: varrun
          emptyDir:
            sizeLimit: 10Mi
        - name: data
          persistentVolumeClaim:
            claimName: %s-data
`, name))
    }

    return b.String()
}

func kustomService(name string, port int) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: %s
  labels:
    app.kubernetes.io/name: %s
spec:
  type: ClusterIP
  trafficDistribution: PreferSameNode
  ports:
    - port: 80
      targetPort: http
      protocol: TCP
      name: http
  selector:
    app.kubernetes.io/name: %s
`, name, name, name)
}

func kustomServiceAccount(name string, secrets ...models.SecretOpts) string {
	var annotationsBlock string
	if len(secrets) > 0 && secrets[0].Provider == "external-secrets" && secrets[0].ESBackendProvider == "aws" {
		roleARN := secrets[0].ESAWSRoleARN
		if roleARN == "" {
			roleARN = "arn:aws:iam::123456789012:role/my-app-role"
		}
		annotationsBlock = fmt.Sprintf(`
    # IRSA — override per overlay with a strategic-merge patch
    eks.amazonaws.com/role-arn: %s`, roleARN)
	} else {
		annotationsBlock = " {}"
	}
	return fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: %s
  labels:
    app.kubernetes.io/name: %s
  annotations:%s
automountServiceAccountToken: false
`, name, name, annotationsBlock)
}

func kustomConfigMap(name string, port int) string {
	return fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: %s-config
  labels:
    app.kubernetes.io/name: %s
data:
  LOG_LEVEL: info
  PORT: "%d"
`, name, name, port)
}

func kustomNetworkPolicy(name string, port int) string {
	return fmt.Sprintf(`# Default deny-all — allowlist model
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s-deny-all
  labels:
    app.kubernetes.io/name: %s
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: %s
  policyTypes:
    - Ingress
    - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s-allow-ingress-controller
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: %s
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: ingress-nginx
      ports:
        - protocol: TCP
          port: %d
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s-allow-dns
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: %s
  policyTypes:
    - Egress
  egress:
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
      to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s-allow-prometheus
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: %s
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
      ports:
        - protocol: TCP
          port: %d
`, name, name, name, name, name, port, name, name, name, name, port)
}

func kustomRBAC(name string) string {
	return fmt.Sprintf(`# Principle of least privilege
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: %s
  labels:
    app.kubernetes.io/name: %s
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch"]
    resourceNames:
      - %s-config
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: %s
  labels:
    app.kubernetes.io/name: %s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: %s
subjects:
  - kind: ServiceAccount
    name: %s
`, name, name, name, name, name, name, name)
}

func kustomHPA(name string) string {
	return fmt.Sprintf(`apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: %s
  labels:
    app.kubernetes.io/name: %s
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: %s
  minReplicas: 2
  maxReplicas: 6
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 10
          periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 30
      policies:
        - type: Percent
          value: 100
          periodSeconds: 30
`, name, name, name)
}

func kustomPVC(name string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: %s-data
  labels:
    app.kubernetes.io/name: %s
  annotations:
    kustomize.config.k8s.io/keep-resource: "true"
spec:
  accessModes:
    - ReadWriteOnce
  volumeMode: Filesystem
  storageClassName: standard
  resources:
    requests:
      storage: 1Gi
`, name, name)
}

// Note: to customize storage class or size, edit the generated PVC
// Example:
// spec:
//   accessModes:
//     - ReadWriteOnce
//   storageClassName: fast
//   resources:
//     requests:
//       storage: 30Gi

func kustomPDB(name string) string {
	return fmt.Sprintf(`apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: %s
  labels:
    app.kubernetes.io/name: %s
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: %s
`, name, name, name)
}

// ─────────────────────────────────────────────
// VPA (Vertical Pod Autoscaler) — Kustomize
// ─────────────────────────────────────────────
func kustomVPA(name string) string {
	return fmt.Sprintf(`# NOTE: VerticalPodAutoscaler requires a VPA controller installed in the cluster.
# Install and enable the VPA controller (or ensure your managed cluster provides it) before applying this manifest.
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: %s-vpa
  labels:
    app.kubernetes.io/name: %s
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: %s
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
      - containerName: %s
        minAllowed:
          cpu: 50m
          memory: 64Mi
        maxAllowed:
          cpu: 1000m
          memory: 512Mi
`, name, name, name, name)
}

// ─────────────────────────────────────────────
// CronJob (Kustomize)
// ─────────────────────────────────────────────
func kustomCronJob(name, image string, sec models.Security) string {
	roVal := "false"
	if sec.ReadOnly {
		roVal = "true"
	}
	privEsc := "true"
	if sec.NoPrivEsc {
		privEsc = "false"
	}
	return fmt.Sprintf(`apiVersion: batch/v1
kind: CronJob
metadata:
  name: %s-job
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/component: cronjob
spec:
  schedule: "0 2 * * *"
  timeZone: "UTC"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 1
  startingDeadlineSeconds: 120
  jobTemplate:
    spec:
      backoffLimit: 3
      activeDeadlineSeconds: 3600
      ttlSecondsAfterFinished: 86400
      template:
        metadata:
          labels:
            app.kubernetes.io/name: %s
            app.kubernetes.io/component: cronjob
        spec:
          restartPolicy: OnFailure
          serviceAccountName: %s
          automountServiceAccountToken: false
          securityContext:
            runAsNonRoot: %s
            runAsUser: 65534
            runAsGroup: 65534
            fsGroup: 65534
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: job
              image: %s
              imagePullPolicy: IfNotPresent
              command: ["/bin/sh", "-c", "echo 'replace-with-job-entrypoint'"]
              securityContext:
                readOnlyRootFilesystem: %s
                allowPrivilegeEscalation: %s
                capabilities:
                  drop: ["ALL"]
                seccompProfile:
                  type: RuntimeDefault
              resources:
                limits:
                  cpu: 200m
                  memory: 128Mi
    
                requests:
                  cpu: 50m
                  memory: 64Mi
    
              volumeMounts:
                - name: tmp
                  mountPath: /tmp
          volumes:
            - name: tmp
              emptyDir:
                sizeLimit: 100Mi
`, name, name, name, name, boolStr(sec.NonRoot), image, roVal, privEsc)
}

// ─────────────────────────────────────────────
// Secret Placeholder (Kustomize)
// ─────────────────────────────────────────────
func kustomSecretPlaceholder(name string) string {
	return fmt.Sprintf(`# ⚠️  Do NOT store plaintext secrets here.
# Use External Secrets Operator or HashiCorp Vault Agent Injector.
# This file is a reference structure only.
#
# Recommended: https://external-secrets.io
#              https://developer.hashicorp.com/vault/docs/platform/k8s
apiVersion: v1
kind: Secret
metadata:
  name: %s-secret
  labels:
    app.kubernetes.io/name: %s
  annotations:
    # Replace with your secret management solution
    managed-by: "replace-me"
type: Opaque
data: {}
`, name, name)
}

// ─────────────────────────────────────────────
// External Secrets (Kustomize)
// ─────────────────────────────────────────────
func kustomExternalSecret(name string, opts models.SecretOpts) string {
	storeName := opts.ESSecretStoreName
	if storeName == "" {
		if opts.ESBackendProvider == "aws" && opts.ESAWSService == "ParameterStore" {
			storeName = "aws-parameterstore"
		} else {
			defaults := map[string]string{"aws": "aws-secretsmanager", "gcp": "gcp-secretmanager", "azure": "azure-keyvault", "vault": "vault-backend"}
			storeName = defaults[opts.ESBackendProvider]
			if storeName == "" {
				storeName = "aws-secretsmanager"
			}
		}
	}
	storeKind := opts.ESSecretStoreKind
	if storeKind == "" {
		storeKind = "SecretStore"
	}
	remotePath := opts.ESRemotePath
	if remotePath == "" {
		switch opts.ESBackendProvider {
		case "gcp":
			remotePath = fmt.Sprintf("projects/-/secrets/%s", name)
		case "azure":
			remotePath = name
		case "vault":
			remotePath = fmt.Sprintf("secret/data/%s", name)
		default: // aws
			if opts.ESAWSService == "ParameterStore" {
				remotePath = fmt.Sprintf("/%s/secrets", name)
			} else {
				remotePath = fmt.Sprintf("%s/secrets", name)
			}
		}
	}
	return fmt.Sprintf(`# ExternalSecret — application-scoped
# Requires: External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: %s-secret
  labels:
    app.kubernetes.io/name: %s
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: %s
    kind: %s
  target:
    name: %s-secret
    creationPolicy: Owner
    deletionPolicy: Retain
    template:
      type: Opaque
      metadata:
        labels:
          app.kubernetes.io/name: %s
  data:
    - secretKey: db_password
      remoteRef:
        key: %s
        property: db_password
    - secretKey: api_key
      remoteRef:
        key: %s
        property: api_key
`, name, name, storeName, storeKind, name, name, remotePath, remotePath)
}

func kustomSecretStore(name string, opts models.SecretOpts) string {
	storeName := opts.ESSecretStoreName
	if storeName == "" {
		if opts.ESBackendProvider == "aws" && opts.ESAWSService == "ParameterStore" {
			storeName = "aws-parameterstore"
		} else {
			defaults := map[string]string{"aws": "aws-secretsmanager", "gcp": "gcp-secretmanager", "azure": "azure-keyvault", "vault": "vault-backend"}
			storeName = defaults[opts.ESBackendProvider]
			if storeName == "" {
				storeName = "aws-secretsmanager"
			}
		}
	}

	var providerBlock string
	switch opts.ESBackendProvider {
	case "gcp":
		projectID := opts.ESGCPProjectID
		if projectID == "" {
			projectID = "my-gcp-project"
		}
		providerBlock = fmt.Sprintf(`    gcpsm:
      projectID: %s
      auth:
        workloadIdentity:
          clusterLocation: us-central1
          clusterName: my-cluster
          serviceAccountRef:
            name: %s
`, projectID, name)
	case "azure":
		vaultURL := opts.ESAzureVaultURL
		if vaultURL == "" {
			vaultURL = "https://my-keyvault.vault.azure.net"
		}
		providerBlock = fmt.Sprintf(`    azurekv:
      vaultUrl: %s
      authType: WorkloadIdentity
      serviceAccountRef:
        name: %s
`, vaultURL, name)
	case "vault":
		server := opts.ESVaultServer
		if server == "" {
			server = "https://vault.example.com"
		}
		vaultPath := opts.ESVaultPath
		if vaultPath == "" {
			vaultPath = "secret"
		}
		role := opts.ESVaultRole
		if role == "" {
			role = name
		}
		providerBlock = fmt.Sprintf(`    vault:
      server: %q
      path: %q
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: %q
          serviceAccountRef:
            name: %s
`, server, vaultPath, role, name)
	default: // "aws"
		region := opts.ESAWSRegion
		if region == "" {
			region = "us-east-1"
		}
		service := opts.ESAWSService
		if service == "" {
			service = "SecretsManager"
		}
		providerBlock = fmt.Sprintf(`    aws:
      service: %s
      region: %s
      auth:
        jwt:
          serviceAccountRef:
            name: %s
`, service, region, name)
	}

	return fmt.Sprintf(`# SecretStore — application-namespace scoped
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: %s
  labels:
    app.kubernetes.io/name: %s
spec:
  provider:
%s`, storeName, name, providerBlock)
}

// ─────────────────────────────────────────────
// Vault (Kustomize)
// ─────────────────────────────────────────────
func kustomVaultSecret(name string, opts models.SecretOpts) string {
	vaultRole := opts.VaultRole
	if vaultRole == "" {
		vaultRole = name
	}
	vaultPath := opts.VaultPath
	if vaultPath == "" {
		vaultPath = fmt.Sprintf("secret/data/%s", name)
	}
	mountPath := opts.VaultMountPath
	if mountPath == "" {
		mountPath = "secret"
	}
	return fmt.Sprintf(`# VaultStaticSecret — application-scoped (Vault Secrets Operator)
apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultStaticSecret
metadata:
  name: %s-vault-secret
  labels:
    app.kubernetes.io/name: %s
spec:
  vaultAuthRef: %s-vault-auth
  mount: %s
  type: kv-v2
  path: %s
  refreshAfter: 1h
  destination:
    name: %s-secret
    create: true
    labels:
      app.kubernetes.io/name: %s
    transformation:
      excludeRaw: true
      templates:
        DB_PASSWORD:
          text: |
            {{ .Secrets.db_password }}
        API_KEY:
          text: |
            {{ .Secrets.api_key }}
`, name, name, name, mountPath, vaultPath, name, name)
}

func kustomVaultAuth(name string, opts models.SecretOpts) string {
	vaultRole := opts.VaultRole
	if vaultRole == "" {
		vaultRole = name
	}
	return fmt.Sprintf(`# VaultAuth — application-scoped
apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultAuth
metadata:
  name: %s-vault-auth
  labels:
    app.kubernetes.io/name: %s
spec:
  vaultConnectionRef: default
  method: kubernetes
  mount: kubernetes
  kubernetes:
    role: %s
    serviceAccount: %s
    audiences:
      - vault
`, name, name, vaultRole, name)
}

// ─────────────────────────────────────────────
// KEDA (Kustomize)
// ─────────────────────────────────────────────
func kustomKedaScaledObject(name string, opts models.KedaOpts) string {
	var triggerBlock string
	switch opts.Trigger {
	case "kafka":
		bs := opts.KafkaBootstrapServers
		if bs == "" {
			bs = "kafka-broker:9092"
		}
		topic := opts.KafkaTopic
		if topic == "" {
			topic = name + "-events"
		}
		cg := opts.KafkaConsumerGroup
		if cg == "" {
			cg = name + "-group"
		}
		lag := opts.KafkaLagThreshold
		if lag == "" {
			lag = "100"
		}
		triggerBlock = fmt.Sprintf(`  triggers:
    - type: kafka
      metadata:
        bootstrapServers: %s
        consumerGroup: %s
        topic: %s
        lagThreshold: "%s"
        offsetResetPolicy: latest
      authenticationRef:
        name: %s-keda-auth
`, bs, cg, topic, lag, name)
	case "rabbitmq":
		queue := opts.RabbitMQQueue
		if queue == "" {
			queue = name + "-queue"
		}
		triggerBlock = fmt.Sprintf(`  triggers:
    - type: rabbitmq
      metadata:
        queueName: %s
        mode: QueueLength
        value: "20"
        protocol: amqp
      authenticationRef:
        name: %s-keda-auth
`, queue, name)
	case "redis":
		listName := opts.RedisListName
		if listName == "" {
			listName = name + "-list"
		}
		triggerBlock = fmt.Sprintf(`  triggers:
    - type: redis
      metadata:
        listName: %s
        listLength: "10"
      authenticationRef:
        name: %s-keda-auth
`, listName, name)
	case "sqs":
		queueURL := opts.SQSQueueURL
		if queueURL == "" {
			queueURL = "https://sqs.us-east-1.amazonaws.com/123456789/my-queue"
		}
		region := opts.SQSRegion
		if region == "" {
			region = "us-east-1"
		}
		triggerBlock = fmt.Sprintf(`  triggers:
    - type: aws-sqs-queue
      metadata:
        queueURL: %s
        queueLength: "5"
        awsRegion: %s
        identityOwner: pod
`, queueURL, region)
	case "prometheus":
		serverAddr := opts.PrometheusServerAddress
		if serverAddr == "" {
			serverAddr = "http://prometheus-server.monitoring.svc.cluster.local"
		}
		query := opts.PrometheusQuery
		if query == "" {
			query = fmt.Sprintf(`sum(rate(http_requests_total{app="%s"}[2m]))`, name)
		}
		triggerBlock = fmt.Sprintf(`  triggers:
    - type: prometheus
      metadata:
        serverAddress: %s
        metricName: http_requests_total
        query: '%s'
        threshold: "100"
        activationThreshold: "10"
`, serverAddr, query)
	case "cron":
		tz := opts.CronTimezone
		if tz == "" {
			tz = "UTC"
		}
		start := opts.CronStart
		if start == "" {
			start = "0 8 * * 1-5"
		}
		end := opts.CronEnd
		if end == "" {
			end = "0 18 * * 1-5"
		}
		desired := opts.CronDesired
		if desired == "" {
			desired = "5"
		}
		triggerBlock = fmt.Sprintf(`  triggers:
    - type: cron
      metadata:
        timezone: %s
        start: "%s"
        end: "%s"
        desiredReplicas: "%s"
`, tz, start, end, desired)
	default:
		triggerBlock = `  triggers: []
`
	}

	return fmt.Sprintf(`# KEDA ScaledObject — event-driven autoscaling
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: %s
  labels:
    app.kubernetes.io/name: %s
    scaledobject.keda.sh/name: %s
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: %s
  minReplicaCount: 1
  maxReplicaCount: 20
  cooldownPeriod: 300
  pollingInterval: 30
  advanced:
    horizontalPodAutoscalerConfig:
      behavior:
        scaleDown:
          stabilizationWindowSeconds: 300
          policies:
            - type: Percent
              value: 10
              periodSeconds: 60
        scaleUp:
          stabilizationWindowSeconds: 30
%s`, name, name, name, name, triggerBlock)
}

func kustomKedaTriggerAuth(name string, opts models.KedaOpts) string {
	var secretRef string
	switch opts.Trigger {
	case "kafka":
		secretRef = fmt.Sprintf(`  secretTargetRef:
    - parameter: sasl
      name: %s-secret
      key: KAFKA_SASL_PASSWORD
    - parameter: username
      name: %s-secret
      key: KAFKA_SASL_USERNAME
`, name, name)
	case "rabbitmq":
		secretRef = fmt.Sprintf(`  secretTargetRef:
    - parameter: host
      name: %s-secret
      key: RABBITMQ_URL
`, name)
	case "redis":
		secretRef = fmt.Sprintf(`  secretTargetRef:
    - parameter: address
      name: %s-secret
      key: REDIS_URL
    - parameter: password
      name: %s-secret
      key: REDIS_PASSWORD
`, name, name)
	default:
		secretRef = fmt.Sprintf(`  secretTargetRef:
    - parameter: connection
      name: %s-secret
      key: BROKER_URL
`, name)
	}
	return fmt.Sprintf(`# TriggerAuthentication — application-scoped broker credentials
apiVersion: keda.sh/v1alpha1
kind: TriggerAuthentication
metadata:
  name: %s-keda-auth
  labels:
    app.kubernetes.io/name: %s
spec:
%s`, name, name, secretRef)
}

// ─────────────────────────────────────────────
// Overlays
// ─────────────────────────────────────────────
func kustomOverlayKustomization(name, imgRepo, imgTag, env string, res map[string]bool, sec models.Security, keda models.KedaOpts) string {
	ns := fmt.Sprintf("%s-%s", name, env)

	var extraResources string
	if res["ingress"] {
		extraResources = `  - patches/ingress.yaml`
	}

	// Build patches list dynamically based on selected resources
	patches := []string{`  - path: patches/deployment-patch.yaml`}
	if res["configmap"] {
		patches = append(patches, `  - path: patches/configmap-patch.yaml`)
	}
	if res["hpa"] && !keda.Enabled {
		patches = append(patches, `  - path: patches/hpa-patch.yaml`)
	}

	switch env {
	case "dev":
		if res["networkpolicy"] && sec.NetPolicy {
			patches = append(patches, `  - path: patches/networkpolicy-patch.yaml`)
		}
	case "prod":
		if res["pdb"] {
			patches = append(patches, `  - path: patches/pdb-patch.yaml`)
		}
	}
	extraPatches := strings.Join(patches, "\n")

	return fmt.Sprintf(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: %s

labels:
  - pairs:
      environment: %s

resources:
  - ../../base
%s

images:
  - name: %s
    newTag: "%s"

patches:
%s
`, ns, env, extraResources, imgRepo, imgTag, extraPatches)
}

func kustomDevDeploymentPatch(name string) string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: %s
          imagePullPolicy: Always
          resources:
            limits:
              cpu: 200m
              memory: 128Mi

            requests:
              cpu: 50m
              memory: 64Mi

`, name, name)
}

func kustomDevIngress(name string) string {
	return fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %s
  annotations: {}
spec:
  ingressClassName: ""
  rules:
    - host: %s-dev.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: %s
                port:
                  number: 80
`, name, name, name)
}

func kustomDevConfigMap(name string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: %s-config
data:
  LOG_LEVEL: debug
  APP_ENV: development
`, name)
}

func kustomDevHPAPatch(name string) string {
	return fmt.Sprintf(`apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: %s
spec:
  minReplicas: 1
  maxReplicas: 3
`, name)
}

func kustomDevNetworkPolicy(name string) string {
	return fmt.Sprintf(`# Dev: relax network policy to allow local debugging
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s-deny-all
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: %s
  policyTypes:
    - Ingress
  # Allow all ingress in dev for easier debugging
  ingress:
    - {}
`, name, name)
}

func kustomStagingDeploymentPatch(name string) string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: %s
          imagePullPolicy: Always
          resources:
            limits:
              cpu: 300m
              memory: 192Mi

            requests:
              cpu: 75m
              memory: 96Mi

`, name, name)
}

func kustomStagingIngress(name string) string {
	return fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %s
  annotations: {}
spec:
  ingressClassName: ""
  tls:
    - secretName: %s-staging-tls
      hosts:
        - %s-staging.example.com
  rules:
    - host: %s-staging.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: %s
                port:
                  number: 80
`, name, name, name, name, name)
}

func kustomStagingConfigMap(name string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: %s-config
data:
  LOG_LEVEL: info
  APP_ENV: staging
`, name)
}

func kustomStagingHPAPatch(name string) string {
	return fmt.Sprintf(`apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: %s
spec:
  minReplicas: 3
  maxReplicas: 6
`, name)
}

func kustomProdDeploymentPatch(name string) string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: %s
          imagePullPolicy: IfNotPresent
          resources:
            limits:
              cpu: 500m
              memory: 256Mi

            requests:
              cpu: 100m
              memory: 128Mi

`, name, name)
}

func kustomProdIngress(name string) string {
	return fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %s
  annotations: {}
spec:
  ingressClassName: ""
  tls:
    - secretName: %s-tls
      hosts:
        - %s.example.com
  rules:
    - host: %s.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: %s
                port:
                  number: 80
`, name, name, name, name, name)
}

func kustomProdHPAPatch(name string) string {
	return fmt.Sprintf(`apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: %s
spec:
  minReplicas: 3
  maxReplicas: 6
`, name)
}

func kustomTestHPAPatch(name string) string {
	return fmt.Sprintf(`apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: %s
spec:
  minReplicas: 1
  maxReplicas: 3
`, name)
}

func kustomTestDeploymentPatch(name string) string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: %s
          imagePullPolicy: Always
          resources:
            limits:
              cpu: 200m
              memory: 128Mi
            requests:
              cpu: 50m
              memory: 64Mi
`, name, name)
}

func kustomProdPDBPatch(name string) string {
	return fmt.Sprintf(`apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: %s
spec:
  minAvailable: 2
`, name)
}

func kustomProdConfigMap(name string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: %s-config
data:
  LOG_LEVEL: warn
  APP_ENV: production
`, name)
}

// ─────────────────────────────────────────────
// README
// ─────────────────────────────────────────────
func kustomReadme(name string, keda models.KedaOpts, secrets models.SecretOpts) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`# %s — Kustomize

Multi-environment Kustomize configuration — K8s 1.29–1.35+ best practices.

## Structure

`+"```"+`
%s/
├── base/              # Shared base manifests
│   ├── kustomization.yaml
│   ├── deployment.yaml
│   └── ...
└── overlays/
    ├── dev/           # Development environment
    ├── staging/       # Staging environment
    └── prod/          # Production environment
`+"```"+`

`, name, name))

	if keda.Enabled {
		b.WriteString(fmt.Sprintf(`## KEDA (%s trigger)

`+"```bash"+`
helm repo add kedacore https://kedacore.github.io/charts
helm install keda kedacore/keda --namespace keda --create-namespace
`+"```"+`

`, keda.Trigger))
	}
	if secrets.Provider == "external-secrets" {
		b.WriteString(`## External Secrets Operator

` + "```bash" + `
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets --create-namespace
` + "```\n\n")
	}
	if secrets.Provider == "vault" {
		b.WriteString(`## Vault Secrets Operator

` + "```bash" + `
helm repo add hashicorp https://helm.releases.hashicorp.com
helm install vault-secrets-operator hashicorp/vault-secrets-operator \
  --namespace vault-secrets-operator --create-namespace
` + "```\n\n")
	}

	b.WriteString(fmt.Sprintf(`## Deploy

### Preview (dry-run)
`+"```bash"+`
kubectl kustomize overlays/dev | kubectl apply --dry-run=client -f -
`+"```"+`

### Development
`+"```bash"+`
kubectl apply -k overlays/dev
kubectl rollout status deployment/%s -n %s-dev
`+"```"+`

### Staging
`+"```bash"+`
kubectl apply -k overlays/staging
kubectl rollout status deployment/%s -n %s-staging --timeout=5m
`+"```"+`

### Production
`+"```bash"+`
kubectl apply -k overlays/prod
kubectl rollout status deployment/%s -n %s-prod --timeout=5m
`+"```"+`

### Rollback
`+"```bash"+`
kubectl rollout undo deployment/%s -n %s-prod
`+"```"+`

### GitOps (FluxCD)
`+"```bash"+`
flux create source git %s --url=https://github.com/org/%s --branch=main
flux create kustomization %s-prod --source=%s --path="./overlays/prod" \
  --prune=true --interval=5m --health-check-timeout=3m
`+"```"+`
`, name, name, name, name, name, name, name, name, name, name, name, name))

	return b.String()
}
// ─────────────────────────────────────────────
// Istio — VirtualService
// ─────────────────────────────────────────────
func kustomVirtualService(name string, istio models.IstiOpts) string {
	gateways := fmt.Sprintf(`- %s`, istio.GatewayName)
	if istio.MeshGateway {
		gateways += "\n  - mesh"
	}
	return fmt.Sprintf(`apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: %s
  namespace: default
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/component: service-mesh
spec:
  hosts:
  - "%s"
  gateways:
  %s
  http:
  - match:
    - uri:
        prefix: /
    route:
    - destination:
        host: "%s"
        port:
          number: %s
      weight: 100
    timeout: 30s
    retries:
      attempts: 3
      perTryTimeout: 10s
`, name, name, name, gateways, name, istio.VirtualServicePort)
}

// ─────────────────────────────────────────────
// Istio — Gateway (cluster-scoped, not generated)
// ─────────────────────────────────────────────
// NOTE: Gateway is a cluster-level resource and should be created separately.
// Reference it by name in VirtualService.gateways field above.

// ─────────────────────────────────────────────
// Istio — DestinationRule
// ─────────────────────────────────────────────
func kustomDestinationRule(name string) string {
	return fmt.Sprintf(`apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: %s
  namespace: default
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/component: service-mesh
spec:
  host: "%s"
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http1MaxPendingRequests: 100
        maxRequestsPerConnection: 2
        h2UpgradePolicy: UPGRADE
    loadBalancer:
      consistentHash:
        httpHeaderName: x-session-id
    outlierDetection:
      consecutive5xxErrors: 5
      interval: 30s
      baseEjectionTime: 30s
      minRequestVolume: 5
      splitExternalLocalOriginErrors: true
  subsets:
  - name: default
    labels:
      version: v1
`, name, name, name)
}

// ─────────────────────────────────────────────
// Istio — EnvoyFilter
// ─────────────────────────────────────────────
func kustomEnvoyFilter(name string) string {
	return fmt.Sprintf(`apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: %s
  namespace: default
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/component: service-mesh
spec:
  workloadSelector:
    labels:
      app.kubernetes.io/name: %s
  configPatches:
  - applyTo: HTTP_FILTER
    match:
      context: SIDECAR_INBOUND
      listener:
        filterChain:
          filter:
            name: "envoy.filters.network.http_connection_manager"
            subFilter:
              name: "envoy.filters.http.router"
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.http.local_ratelimit
        typedConfig:
          "@type": type.googleapis.com/udpa.type.v1.TypedStruct
          typeUrl: type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
          value:
            stat_prefix: http_local_rate_limiter
            token_bucket:
              max_tokens: 100
              tokens_per_fill: 100
              fill_interval: 1s
            filter_enabled:
              runtime_key: local_rate_limit_enabled
              default_value:
                numerator: 100
                denominator: HUNDRED
            filter_enforced:
              runtime_key: local_rate_limit_enforced
              default_value:
                numerator: 100
                denominator: HUNDRED
            response_headers_to_add:
            - append_action: OVERWRITE_IF_EXISTS_OR_ADD
              header:
                key: x-local-rate-limit
                value: "true"
`, name, name, name)
}

// ─────────────────────────────────────────────
// Istio — AuthorizationPolicy
// ─────────────────────────────────────────────
func kustomAuthorizationPolicy(name string, istio models.IstiOpts) string {
	return fmt.Sprintf(`apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: %s
  namespace: default
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/component: service-mesh
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: %s
  action: %s
  rules:
  # Allow requests from same namespace
  - from:
    - source:
        namespaces:
        - default
    to:
    - operation:
        methods:
        - GET
        - POST
        - PUT
        - DELETE
        - PATCH
        - OPTIONS
  # Allow health checks
  - to:
    - operation:
        paths:
        - /healthz*
        - /readyz*
`, name, name, name, istio.AuthzPolicyAction)
}