package generator

import (
  "fmt"
  "strings"
  "strconv"

  "k8s-blueprint/internal/models"
)

// GenerateHelm returns all files for a Helm chart
func GenerateHelm(req models.BlueprintRequest) []models.GeneratedFile {
	name := req.AppName
	img := req.Image
  // Port is provided as a string (to preserve formatting); parse to int with fallback
  port := 8080
  if req.Port != "" {
    if p, err := strconv.Atoi(req.Port); err == nil {
      port = p
    }
  }
  res := toSet(req.Resources)
  // If a secrets provider is selected in the UI, ensure secret templates are generated
  if req.Secrets.Provider != "" && req.Secrets.Provider != "none" {
    res["secret"] = true
  }
	envs := req.Envs
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

	add("Chart.yaml", helmChartYaml(name))
  add("values.yaml", helmValuesBase(name, imgRepo, imgTag, port, sec, res, req.Secrets))
  // Only emit per-env override files for environments requested by the user
  envSet := toSet(envs)
  if envSet["dev"] {
    add("values-dev.yaml", helmValuesDev(name, imgRepo, res))
  }
  if envSet["test"] {
    add("values-test.yaml", helmValuesTest(name, imgRepo, res))
  }
  if envSet["staging"] {
    add("values-staging.yaml", helmValuesStaging(name, imgRepo, res))
  }
  if envSet["prod"] {
    add("values-prod.yaml", helmValuesProd(name, imgRepo, res))
  }
	add("templates/_helpers.tpl", helmHelpers(name))
  add("templates/deployment.yaml", helmDeployment(name, port, sec, res))
	if res["service"] {
		add("templates/service.yaml", helmService(name))
	}
	if res["serviceaccount"] {
		add("templates/serviceaccount.yaml", helmServiceAccount(name))
	}
	if res["ingress"] {
		add("templates/ingress.yaml", helmIngress(name))
	}
	if res["configmap"] {
		add("templates/configmap.yaml", helmConfigMap(name))
	}
	if res["hpa"] {
		if !req.Keda.Enabled {
			add("templates/hpa.yaml", helmHPA(name))
		}
	}
  // Vertical Pod Autoscaler (VPA) - optional
  if res["vpa"] {
    add("templates/vpa.yaml", helmVPA(name))
  }
	if res["networkpolicy"] && sec.NetPolicy {
		add("templates/networkpolicy.yaml", helmNetworkPolicy(name, port))
	}
	if res["rbac"] {
		add("templates/role.yaml", helmRole(name))
		add("templates/rolebinding.yaml", helmRoleBinding(name))
	}
	if res["pvc"] {
		add("templates/pvc.yaml", helmPVC(name))
	}
	if res["pdb"] {
		add("templates/pdb.yaml", helmPDB(name))
	}
	if res["cronjob"] {
    add("templates/cronjob.yaml", helmCronJob(name, img, sec, res))
	}
	if res["secret"] {
		if req.Secrets.Provider == "external-secrets" {
			add("templates/externalsecret.yaml", helmExternalSecret(name, req.Secrets))
			add("templates/secretstore.yaml", helmSecretStore(name, req.Secrets))
		} else if req.Secrets.Provider == "vault" {
			add("templates/vault-secret.yaml", helmVaultSecret(name, req.Secrets))
			add("templates/vault-auth.yaml", helmVaultAuth(name, req.Secrets))
		} else {
			add("templates/secret.yaml", helmSecretPlaceholder(name))
		}
	}
	if req.Keda.Enabled {
		add("templates/keda-scaledobject.yaml", helmKedaScaledObject(name, req.Keda))
		if req.Keda.Trigger == "kafka" || req.Keda.Trigger == "rabbitmq" || req.Keda.Trigger == "redis" {
			add("templates/keda-auth.yaml", helmKedaTriggerAuth(name, req.Keda))
		}
	}
	if req.Istio.Enabled {
		add("templates/virtualservice.yaml", helmVirtualService(name, req.Istio))
		if req.Istio.DestinationRule {
			add("templates/destinationrule.yaml", helmDestinationRule(name))
		}
		if req.Istio.EnvoyFilter {
			add("templates/envoyfilter.yaml", helmEnvoyFilter(name))
		}
		if req.Istio.AuthorizationPolicy {
			add("templates/authorizationpolicy.yaml", helmAuthorizationPolicy(name, req.Istio))
		}
	}
	add(".helmignore", helmIgnore())

	for _, env := range envs {
		_ = env // values files already added above
	}

	return files
}

// ─────────────────────────────────────────────
// Chart.yaml
// ─────────────────────────────────────────────
func helmChartYaml(name string) string {
	return fmt.Sprintf(`apiVersion: v2
name: %s
description: Production-grade Helm chart for %s — K8s 1.35+ best practices
type: application
version: 0.1.0
appVersion: "1.0.0"
kubeVersion: ">=1.29.0"
keywords:
  - %s
maintainers:
  - name: platform-team
    email: platform@example.com
annotations:
  category: Application
  artifacthub.io/license: Apache-2.0
`, name, name, name)
}

// ─────────────────────────────────────────────
// values.yaml
// ─────────────────────────────────────────────
func helmValuesBase(name, imgRepo, imgTag string, port int, sec models.Security, res map[string]bool, secrets ...models.SecretOpts) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`# =================================================================
# %s — default values  (override per env in values-{env}.yaml)
# Targeting Kubernetes >=1.29  (compatible up to 1.35+)
# =================================================================

replicaCount: 2

image:
  repository: %s
  tag: %q
  pullPolicy: IfNotPresent
  pullSecrets: []

nameOverride: ""
fullnameOverride: ""
`, name, imgRepo, imgTag))

	if res["serviceaccount"] {
		// Build SA annotations block — IRSA annotation when AWS ESO is selected
		var saAnnotationsBlock string
		if len(secrets) > 0 && secrets[0].Provider == "external-secrets" && secrets[0].ESBackendProvider == "aws" {
			roleARN := secrets[0].ESAWSRoleARN
			if roleARN == "" {
				roleARN = "arn:aws:iam::123456789012:role/my-app-role"
			}
			saAnnotationsBlock = fmt.Sprintf(`
    # IRSA — override per environment in values-{env}.yaml
    eks.amazonaws.com/role-arn: %s`, roleARN)
		} else {
			saAnnotationsBlock = " {}"
		}
		b.WriteString(fmt.Sprintf(`# ── Service Account ──────────────────────────────────────────────
serviceAccount:
  create: true
  annotations:%s
  # Never auto-mount — use explicit volumeMount if needed
  automountServiceAccountToken: false

`, saAnnotationsBlock))
	}

	b.WriteString(fmt.Sprintf(`# ── Pod metadata ─────────────────────────────────────────────────
podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: %q
podLabels: {}

# ── Pod-level Security Context ───────────────────────────────────
# CIS Kubernetes Benchmark v1.9 + NSA Hardening Guidance
podSecurityContext:
`, fmt.Sprintf("%d", port)))

	if sec.NonRoot {
		b.WriteString(`  runAsNonRoot: true
  runAsUser: 65534
  runAsGroup: 65534
  fsGroup: 65534
  fsGroupChangePolicy: OnRootMismatch
`)
	}
	if sec.Seccomp {
		b.WriteString(`  seccompProfile:
    type: RuntimeDefault
`)
	}
	b.WriteString(`  sysctls: []

# ── Container-level Security Context ─────────────────────────────
containerSecurityContext:
`)
	if sec.ReadOnly {
		b.WriteString(`  readOnlyRootFilesystem: true
`)
	}
	if sec.NonRoot {
		b.WriteString(`  runAsNonRoot: true
  runAsUser: 65534
`)
	}
	if sec.DropCaps {
		b.WriteString(`  capabilities:
    drop:
      - ALL
`)
	}
	if sec.NoPrivEsc {
		b.WriteString(`  allowPrivilegeEscalation: false
`)
	}
	if sec.Seccomp {
		b.WriteString(`  seccompProfile:
    type: RuntimeDefault
`)
	}
	b.WriteString(fmt.Sprintf(`
# ── Scheduling ────────────────────────────────────────────────────
nodeSelector: {}
tolerations: []

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

# Zone-spread for HA (K8s 1.26+ — MinDomains stable)
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: %s
    minDomains: 3

# ── Service configuration (transparent defaults)
service:
  type: ClusterIP
  trafficDistribution: PreferSameNode
  port: %d
  protocol: TCP

# ── Resources ────────────────────────────────────────────────────
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi

# ── Probes ───────────────────────────────────────────────────────
livenessProbe:
  httpGet:
    path: /healthz
    port: http
  initialDelaySeconds: 15
  periodSeconds: 20
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /readyz
    port: http
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3

startupProbe:
  httpGet:
    path: /healthz
    port: http
  failureThreshold: 30
  periodSeconds: 10

# ── Autoscaling ──────────────────────────────────────────────────
autoscaling:
  enabled: false
  minReplicas: 2
  maxReplicas: 6
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
  scaleDownStabilizationWindowSeconds: 300

# ── Volumes (transparent defaults for tmp dirs used by Deployment)
volumes:
  tmpDir:
    enabled: false
    sizeLimit: 100Mi

# ── Persistent Volume Claim (optional)
# 'pvc.enabled' controls whether a PVC is created; by default we provide
# a tmpDir-backed PVC configuration below. To provision a specific
# storage class or request more storage, override the 'pvc.claim' fields
# in your values.yaml or environment overlay.
pvc:
  enabled: false
  # Use an existing claim instead of creating one
  useExistingClaim: false
  # tmpDir: when true mounts a tmp volume backed by an application PVC
  tmpDir:
    enabled: true
  # Claim template (used when creating a new PVC)
  claim:
    accessModes:
      - ReadWriteOnce
    storageClassName: standard
    resources:
      requests:
        storage: 1Gi
`, name, name, port))

	// Only include networkPolicy if selected
	if res["networkpolicy"] {
		b.WriteString(`# ── Network Policy ────────────────────────────────────────────────
networkPolicy:
  enabled: true
`)
	}

	if res["pdb"] {
		b.WriteString(`# ── PodDisruptionBudget ───────────────────────────────────────────
podDisruptionBudget:
  enabled: true
  minAvailable: 1

`)
	}

	if res["configmap"] {
		b.WriteString(fmt.Sprintf(`# ── Application config (mounted as ConfigMap) ─────────────────────
config:
  LOG_LEVEL: info
  PORT: %q
`, fmt.Sprintf("%d", port)))
	}

	return b.String()
}

func helmValuesDev(name, imgRepo string, res map[string]bool) string {
	return fmt.Sprintf(`# ── Development overrides ────────────────────────────────────────
replicaCount: 1

image:
  tag: "latest"
  pullPolicy: Always

resources:
  limits:
    cpu: 200m
    memory: 128Mi

  requests:
    cpu: 50m
    memory: 64Mi


autoscaling:
  enabled: true
  minReplicas: 1
  maxReplicas: 3

topologySpreadConstraints: []

affinity: {}
`) +
		func() string {
			if res["ingress"] {
				return fmt.Sprintf(`ingress:
  enabled: true
  hosts:
    - host: %s-dev.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: %s-dev-tls
      hosts:
        - %s-dev.example.com

`, name, name, name)
			}
			return ""
		}() +
		fmt.Sprintf(`config:
  LOG_LEVEL: debug
  APP_ENV: development
`)
}

func helmValuesStaging(name, imgRepo string, res map[string]bool) string {
	return fmt.Sprintf(`# ── Staging overrides ────────────────────────────────────────────
replicaCount: 2

image:
  tag: "staging"
  pullPolicy: Always

resources:
  limits:
    cpu: 300m
    memory: 192Mi

  requests:
    cpu: 75m
    memory: 96Mi


autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 6

`) +
		func() string {
			if res["ingress"] {
				return fmt.Sprintf(`ingress:
  enabled: true
  hosts:
    - host: %s-staging.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: %s-staging-tls
      hosts:
        - %s-staging.example.com

`, name, name, name)
			}
			return ""
		}() +
		fmt.Sprintf(`config:
  LOG_LEVEL: info
  APP_ENV: staging
`)
}

func helmValuesTest(name, imgRepo string, res map[string]bool) string {
    return fmt.Sprintf(`# ── Test overrides ─────────────────────────────────────────────—
replicaCount: 1

image:
  tag: "test"
  pullPolicy: Always

resources:
  limits:
    cpu: 200m
    memory: 128Mi
  requests:
    cpu: 50m
    memory: 64Mi

autoscaling:
  enabled: true
  minReplicas: 1
  maxReplicas: 3

`) +
        func() string {
            if res["ingress"] {
                return fmt.Sprintf(`ingress:
  enabled: true
  hosts:
    - host: %s-test.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: %s-test-tls
      hosts:
        - %s-test.example.com

`, name, name, name)
            }
            return ""
        }() +
        fmt.Sprintf(`config:
  LOG_LEVEL: debug
  APP_ENV: test
`)
}

func helmValuesProd(name, imgRepo string, res map[string]bool) string {
	return fmt.Sprintf(`# ── Production overrides ─────────────────────────────────────────
replicaCount: 3

image:
  tag: "1.0.0"
  pullPolicy: IfNotPresent

resources:
  limits:
    cpu: 500m
    memory: 256Mi

  requests:
    cpu: 100m
    memory: 128Mi


autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 6

podDisruptionBudget:
  enabled: true
  minAvailable: 2

`) +
		func() string {
			if res["ingress"] {
				return fmt.Sprintf(`ingress:
  enabled: true
  hosts:
    - host: %s.example.com
      paths:
        - path: /
          pathType: Prefix

`, name)
			}
			return ""
		}() +
		fmt.Sprintf(`config:
  LOG_LEVEL: warn
  APP_ENV: production
`)
}

// ─────────────────────────────────────────────
// _helpers.tpl
// ─────────────────────────────────────────────
func helmHelpers(name string) string {
	return fmt.Sprintf(`{{/*
Expand the name of the chart.
*/}}
{{- define "%s.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncated at 63 chars (DNS label limit).
*/}}
{{- define "%s.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%%s-%%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label.
*/}}
{{- define "%s.chart" -}}
{{- printf "%%s-%%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels — Kubernetes recommended label set.
https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/
*/}}
{{- define "%s.labels" -}}
helm.sh/chart: {{ include "%s.chart" . }}
{{ include "%s.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: {{ .Chart.Name }}
app.kubernetes.io/component: server
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "%s.selectorLabels" -}}
app.kubernetes.io/name: {{ include "%s.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "%s.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "%s.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
`, name, name, name, name, name, name, name, name, name, name)
}

// ─────────────────────────────────────────────
// templates/deployment.yaml
// ─────────────────────────────────────────────
func helmDeployment(name string, port int, sec models.Security, res map[string]bool) string {
    var b strings.Builder

    b.WriteString(fmt.Sprintf(`{{- /*
  Deployment — %s
  Security: CIS K8s Benchmark v1.9 + NSA Hardening + Pod Security Standards (Restricted)
  K8s 1.35+ features: in-place resource resize, sidecar containers, topology-aware routing
*/ -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "%s.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
spec:
  {{- if not .Values.autoscaling.enabled }}
  replicas: {{ .Values.replicaCount }}
  {{- end }}
  selector:
    matchLabels:
      {{- include "%s.selectorLabels" . | nindent 6 }}
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  revisionHistoryLimit: 3
  progressDeadlineSeconds: 600
  template:
    metadata:
      annotations:
`, name, name, name, name))

    // Only include configmap checksum if configmap is selected
    if res["configmap"] {
        b.WriteString(`        # Force pod restart when ConfigMap changes
        checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
`)
    }

    b.WriteString(fmt.Sprintf(`        {{- with .Values.podAnnotations }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      labels:
        {{- include "%s.selectorLabels" . | nindent 8 }}
        {{- with .Values.podLabels }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
    spec:
      {{- with .Values.image.pullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
`, name))

    // Only reference serviceAccount if selected
    if res["serviceaccount"] {
        b.WriteString(fmt.Sprintf(`      serviceAccountName: {{ include "%s.serviceAccountName" . }}
`, name))
    }

    b.WriteString(`      automountServiceAccountToken: false
      securityContext:
        {{- toYaml .Values.podSecurityContext | nindent 8 }}
      terminationGracePeriodSeconds: 60
      {{- with .Values.topologySpreadConstraints }}
      topologySpreadConstraints:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          securityContext:
            {{- toYaml .Values.containerSecurityContext | nindent 12 }}
          ports:
            - name: http
`)

    b.WriteString(fmt.Sprintf(`              containerPort: %d
              protocol: TCP
`, port))

    // Build envFrom block based on selected resources
    if res["configmap"] || res["secret"] {
        b.WriteString(`          envFrom:
`)
        if res["configmap"] {
            b.WriteString(fmt.Sprintf(`            - configMapRef:
                name: {{ include "%s.fullname" . }}-config
`, name))
        }
        if res["secret"] {
            b.WriteString(fmt.Sprintf(`            - secretRef:
                name: {{ include "%s.fullname" . }}-secret
`, name))
        }
    }

    b.WriteString(`          {{- with .Values.envFrom }}
            {{- toYaml . | nindent 12 }}
          {{- end }}
          {{- with .Values.env }}
          env:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          livenessProbe:
            {{- toYaml .Values.livenessProbe | nindent 12 }}
          readinessProbe:
            {{- toYaml .Values.readinessProbe | nindent 12 }}
          startupProbe:
            {{- toYaml .Values.startupProbe | nindent 12 }}
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
`)

    s := b.String()

    // Add volumeMounts + volumes when PVC is selected
    if res["pvc"] {
        s += `          volumeMounts:
            {{- if .Values.pvc.tmpDir.enabled }}
            - name: tmp
              mountPath: /tmp
            - name: varrun
              mountPath: /var/run
            {{- end }}
            {{- if .Values.pvc.enabled }}
            - name: data
              mountPath: /data
            {{- end }}
`
    }

    // append the remaining sections

    // Add volumes block when PVC is selected
    if res["pvc"] {
        s += fmt.Sprintf(`      volumes:
        {{- if .Values.pvc.tmpDir.enabled }}
        - name: tmp
          emptyDir:
            sizeLimit: 100Mi
        - name: varrun
          emptyDir:
            sizeLimit: 10Mi
        {{- end }}
        {{- if .Values.pvc.enabled }}
        - name: data
          persistentVolumeClaim:
            claimName: {{ include "%s.fullname" . }}-data
        {{- end }}
`, name)
    }

    s += `      {{- with .Values.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.affinity }}
      affinity:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
`

    return s
}
func helmService(name string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: {{ include "%s.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
spec:
  type: {{ default "ClusterIP" .Values.service.type }}
  trafficDistribution: {{ default "PreferSameNode" .Values.service.trafficDistribution }}
  ports:
    - port: {{ default 80 .Values.service.port }}
      targetPort: http
      protocol: {{ default "TCP" .Values.service.protocol }}
      name: http
  selector:
    {{- include "%s.selectorLabels" . | nindent 4 }}
`, name, name, name)
}

func helmServiceAccount(name string) string {
	return fmt.Sprintf(`{{- if .Values.serviceAccount.create -}}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "%s.serviceAccountName" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
  {{- with .Values.serviceAccount.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
# Never auto-mount — use explicit projected volumes if IRSA/Workload Identity needed
automountServiceAccountToken: false
{{- end }}
`, name, name)
}

func helmIngress(name string) string {
	return fmt.Sprintf(`{{- if .Values.ingress.enabled -}}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "%s.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
  {{- with .Values.ingress.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  {{- if .Values.ingress.className }}
  ingressClassName: {{ .Values.ingress.className }}
  {{- end }}
  {{- if .Values.ingress.tls }}
  tls:
    {{- toYaml .Values.ingress.tls | nindent 4 }}
  {{- end }}
  rules:
    {{- range .Values.ingress.hosts }}
    - host: {{ .host | quote }}
      http:
        paths:
          {{- range .paths }}
          - path: {{ .path }}
            pathType: {{ .pathType }}
            backend:
              service:
                name: {{ include "%s.fullname" $ }}
                port:
                  number: {{ default 80 $.Values.service.port }}
          {{- end }}
    {{- end }}
{{- end }}
`, name, name, name)
}

func helmConfigMap(name string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "%s.fullname" . }}-config
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
  annotations:
    # checksum ensures pods restart on config change (handled in Deployment)
    config-hash: {{ toYaml .Values.config | sha256sum }}
data:
  {{- toYaml .Values.config | nindent 2 }}
`, name, name)
}

func helmHPA(name string) string {
	return fmt.Sprintf(`# HPA v2 — always enabled (disabled via minReplicaCount with KEDA)
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ include "%s.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ include "%s.fullname" . }}
  minReplicas: {{ .Values.autoscaling.minReplicas }}
  maxReplicas: {{ .Values.autoscaling.maxReplicas }}
  metrics:
    {{- if .Values.autoscaling.targetCPUUtilizationPercentage }}
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: {{ .Values.autoscaling.targetCPUUtilizationPercentage }}
    {{- end }}
    {{- if .Values.autoscaling.targetMemoryUtilizationPercentage }}
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: {{ .Values.autoscaling.targetMemoryUtilizationPercentage }}
    {{- end }}
  behavior:
    scaleDown:
      stabilizationWindowSeconds: {{ .Values.autoscaling.scaleDownStabilizationWindowSeconds }}
      policies:
        - type: Percent
          value: 10
          periodSeconds: 60
        - type: Pods
          value: 2
          periodSeconds: 60
      selectPolicy: Min
    scaleUp:
      stabilizationWindowSeconds: 30
      policies:
        - type: Percent
          value: 100
          periodSeconds: 30
        - type: Pods
          value: 4
          periodSeconds: 30
      selectPolicy: Max
`, name, name, name)
}

func helmNetworkPolicy(name string, port int) string {
	return fmt.Sprintf(`{{- if .Values.networkPolicy.enabled }}
# ── Default: deny all ingress + egress ───────────────────────────
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "%s.fullname" . }}-deny-all
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
spec:
  podSelector:
    matchLabels:
      {{- include "%s.selectorLabels" . | nindent 6 }}
  policyTypes:
    - Ingress
    - Egress
---
# ── Allow ingress from NGINX ingress controller ───────────────────
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "%s.fullname" . }}-allow-ingress
  namespace: {{ .Release.Namespace }}
spec:
  podSelector:
    matchLabels:
      {{- include "%s.selectorLabels" . | nindent 6 }}
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
# ── Allow DNS egress (CoreDNS) ────────────────────────────────────
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "%s.fullname" . }}-allow-dns
  namespace: {{ .Release.Namespace }}
spec:
  podSelector:
    matchLabels:
      {{- include "%s.selectorLabels" . | nindent 6 }}
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
# ── Allow Prometheus scraping ─────────────────────────────────────
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "%s.fullname" . }}-allow-prometheus
  namespace: {{ .Release.Namespace }}
spec:
  podSelector:
    matchLabels:
      {{- include "%s.selectorLabels" . | nindent 6 }}
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
{{- end }}
`, name, name, name, name, name, port, name, name, name, name, port)
}

func helmRole(name string) string {
	return fmt.Sprintf(`{{- if .Values.serviceAccount.create }}
# Principle of least privilege: only the exact permissions required
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "%s.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch"]
    resourceNames:
      - {{ include "%s.fullname" . }}-config
  # Uncomment if reading own secrets is needed
  # - apiGroups: [""]
  #   resources: ["secrets"]
  #   verbs: ["get"]
  #   resourceNames:
  #     - {{ include "%s.fullname" . }}-secret
{{- end }}
`, name, name, name, name)
}

func helmRoleBinding(name string) string {
	return fmt.Sprintf(`{{- if .Values.serviceAccount.create }}
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "%s.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "%s.fullname" . }}
subjects:
  - kind: ServiceAccount
    name: {{ include "%s.serviceAccountName" . }}
    namespace: {{ .Release.Namespace }}
{{- end }}
`, name, name, name, name)
}

func helmPVC(name string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ include "%s.fullname" . }}-data
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
  annotations:
    # Prevent Helm from deleting PVC on uninstall
    "helm.sh/resource-policy": keep
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: standard
  volumeMode: Filesystem
  resources:
    requests:
      storage: 1Gi
`, name, name)
}

func helmPDB(name string) string {
	return fmt.Sprintf(`# PodDisruptionBudget — ensures availability during voluntary disruptions
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ include "%s.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
spec:
  minAvailable: {{ .Values.podDisruptionBudget.minAvailable }}
  selector:
    matchLabels:
      {{- include "%s.selectorLabels" . | nindent 6 }}
  # unhealthyPodEvictionPolicy: AlwaysAllow  # K8s 1.27+ - evict unhealthy pods first
`, name, name, name)
}

func helmCronJob(name, image string, sec models.Security, res map[string]bool) string {
    roVal := "false"
    if sec.ReadOnly {
        roVal = "true"
    }
    privEsc := "true"
    if sec.NoPrivEsc {
        privEsc = "false"
    }

    s := fmt.Sprintf(`apiVersion: batch/v1
kind: CronJob
metadata:
  name: {{ include "%s.fullname" . }}-job
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
    app.kubernetes.io/component: cronjob
spec:
  schedule: "0 2 * * *"
  timeZone: "UTC"                   # K8s 1.27+ stable
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
            {{- include "%s.selectorLabels" . | nindent 12 }}
            app.kubernetes.io/component: cronjob
        spec:
          restartPolicy: OnFailure
          serviceAccountName: {{ include "%s.serviceAccountName" . }}
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
              image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
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
              
`, name, name, name, name, boolStr(sec.NonRoot), roVal, privEsc)

    // remove tmp mount/volume when PVC not selected
    if !res["pvc"] {
        s = strings.Replace(s, "              volumeMounts:\n                - name: tmp\n                  mountPath: /tmp\n          volumes:\n            - name: tmp\n              emptyDir:\n                sizeLimit: 100Mi\n", "", 1)
    }

    return s
}

func helmSecretPlaceholder(name string) string {
    return fmt.Sprintf(`# ⚠️  Do NOT store plaintext secrets here.
# Use External Secrets Operator or HashiCorp Vault Agent Injector.
# This file is a reference structure only.
#
# Recommended: https://external-secrets.io
#              https://developer.hashicorp.com/vault/docs/platform/k8s
apiVersion: v1
kind: Secret
metadata:
  name: {{ include "%s.fullname" . }}-secret
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
  annotations:
    # Replace with your secret management solution
    managed-by: "replace-me"
type: Opaque
data: {}
`, name, name)
}

// ─────────────────────────────────────────────
// External Secrets
// ─────────────────────────────────────────────
func helmExternalSecret(name string, opts models.SecretOpts) string {
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
	return fmt.Sprintf(`# ExternalSecret — application-scoped secret sync
# Requires: External Secrets Operator (https://external-secrets.io)
# Install ESO: helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: {{ include "%s.fullname" . }}-secret
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
spec:
  # Sync interval — reduce in prod to detect rotation faster
  refreshInterval: 1h

  # Reference the SecretStore (or ClusterSecretStore) that holds provider config
  secretStoreRef:
    name: %s
    kind: %s

  # Kubernetes Secret that ESO will create/update
  target:
    name: {{ include "%s.fullname" . }}-secret
    creationPolicy: Owner
    deletionPolicy: Retain
    template:
      type: Opaque
      metadata:
        labels:
          {{- include "%s.labels" . | nindent 10 }}
      data:
        # Example: map remote key → local key
        DB_PASSWORD: "{{ .db_password }}"
        API_KEY: "{{ .api_key }}"

  # Remote secret path in the provider
  data:
    - secretKey: db_password
      remoteRef:
        key: %s
        property: db_password
    - secretKey: api_key
      remoteRef:
        key: %s
        property: api_key

  # Alternatively use dataFrom to sync all keys at once:
  # dataFrom:
  #   - extract:
  #       key: %s
`, name, name, storeName, storeKind, name, name, remotePath, remotePath, remotePath)
}

func helmSecretStore(name string, opts models.SecretOpts) string {
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
            name: {{ include "%s.serviceAccountName" . }}
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
        name: {{ include "%s.serviceAccountName" . }}
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
            name: {{ include "%s.serviceAccountName" . }}
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
            name: {{ include "%s.serviceAccountName" . }}
`, service, region, name)
	}

	return fmt.Sprintf(`# SecretStore — application-namespace scoped provider configuration
# For cross-namespace sharing use ClusterSecretStore instead.
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: %s
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
spec:
  provider:
%s`, storeName, name, providerBlock)
}

// ─────────────────────────────────────────────
// Vault Agent Injector
// ─────────────────────────────────────────────
func helmVaultSecret(name string, opts models.SecretOpts) string {
	vaultAddr := opts.VaultAddress
	if vaultAddr == "" {
		vaultAddr = "https://vault.example.com"
	}
	vaultRole := opts.VaultRole
	if vaultRole == "" {
		vaultRole = name
	}
	vaultPath := opts.VaultPath
	if vaultPath == "" {
		vaultPath = fmt.Sprintf("secret/data/%s", name)
	}
	return fmt.Sprintf(`# Vault Agent Injector — application-scoped annotations
# Requires: Vault Agent Injector installed in cluster (cluster-bootstrap concern)
# Docs: https://developer.hashicorp.com/vault/docs/platform/k8s/injector
#
# These annotations live on the Deployment pod template.
# Add them under .Values.podAnnotations in values.yaml:
#
# podAnnotations:
#   vault.hashicorp.com/agent-inject: "true"
#   vault.hashicorp.com/role: "%s"
#   vault.hashicorp.com/agent-inject-secret-config: "%s"
#   vault.hashicorp.com/agent-inject-template-config: |
#     {{- with secret "%s" -}}
#     DB_PASSWORD="{{ .Data.data.db_password }}"
#     API_KEY="{{ .Data.data.api_key }}"
#     {{- end }}
#   vault.hashicorp.com/agent-pre-populate-only: "false"
#   vault.hashicorp.com/agent-run-as-user: "65534"
#   vault.hashicorp.com/tls-skip-verify: "false"

# ── VaultAuth (Vault Secrets Operator — application-scoped) ───────
# Alternative to injector: use Vault Secrets Operator (VSO)
# https://developer.hashicorp.com/vault/docs/platform/k8s/vso
apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultStaticSecret
metadata:
  name: {{ include "%s.fullname" . }}-vault-secret
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
spec:
  # Reference the VaultAuth resource for this application
  vaultAuthRef: {{ include "%s.fullname" . }}-vault-auth
  mount: %s
  type: kv-v2
  path: %s
  refreshAfter: 1h
  destination:
    name: {{ include "%s.fullname" . }}-secret
    create: true
    labels:
      {{- include "%s.labels" . | nindent 6 }}
`, vaultRole, vaultPath, vaultPath, name, name, name,
		func() string {
			if opts.VaultMountPath != "" {
				return opts.VaultMountPath
			}
			return "secret"
		}(),
		vaultPath, name, name)
}

func helmVaultAuth(name string, opts models.SecretOpts) string {
	vaultRole := opts.VaultRole
	if vaultRole == "" {
		vaultRole = name
	}
	vaultAddr := opts.VaultAddress
	if vaultAddr == "" {
		vaultAddr = "https://vault.example.com"
	}
	return fmt.Sprintf(`# VaultAuth — application-scoped Vault authentication config
# Used by Vault Secrets Operator to authenticate this app to Vault.
# Cluster-level VaultConnection is a separate bootstrap concern.
apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultAuth
metadata:
  name: {{ include "%s.fullname" . }}-vault-auth
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
spec:
  # VaultConnection is cluster-scoped (bootstrap) — reference it here
  vaultConnectionRef: default  # created by platform team
  method: kubernetes
  mount: kubernetes
  kubernetes:
    role: %s
    serviceAccount: {{ include "%s.serviceAccountName" . }}
    audiences:
      - vault
  # Optional: token TTL and renewal
  # tokenExpirationSeconds: 7200
`, name, name, vaultRole, name)
}

// ─────────────────────────────────────────────
// KEDA
// ─────────────────────────────────────────────
func helmKedaScaledObject(name string, opts models.KedaOpts) string {
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
        # Offset reset policy when no consumer group exists
        offsetResetPolicy: latest
        # Scale to zero when lag = 0
        scaleToZeroOnInvalidOffset: "false"
        # TLS (enable if broker requires mTLS)
        # tls: enable
        # saslType: plaintext
      # Reference TriggerAuthentication for SASL/TLS credentials
      authenticationRef:
        name: {{ include "%s.fullname" . }}-keda-auth
`, bs, cg, topic, lag, name)
	case "rabbitmq":
		queue := opts.RabbitMQQueue
		if queue == "" {
			queue = name + "-queue"
		}
		host := opts.RabbitMQHost
		if host == "" {
			host = "amqp://rabbitmq:5672"
		}
		triggerBlock = fmt.Sprintf(`  triggers:
    - type: rabbitmq
      metadata:
        queueName: %s
        mode: QueueLength
        value: "20"
        # Protocol: amqp | http
        protocol: amqp
        # vhost: /
      authenticationRef:
        name: {{ include "%s.fullname" . }}-keda-auth
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
        enableTLS: "false"
      authenticationRef:
        name: {{ include "%s.fullname" . }}-keda-auth
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
        # Use IRSA (IAM Roles for Service Accounts) — no credentials in manifests
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
        # Activate when above threshold, deactivate when below
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
  # Configure a trigger type: kafka | rabbitmq | redis | sqs | prometheus | cron
`
	}

	return fmt.Sprintf(`# KEDA ScaledObject — event-driven autoscaling
# Requires: KEDA v2 installed in cluster (https://keda.sh)
# Install: helm install keda kedacore/keda --namespace keda --create-namespace
#
# KEDA replaces HPA for this deployment when enabled.
# The ScaledObject creates and manages an HPA under the hood.
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: {{ include "%s.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
    scaledobject.keda.sh/name: {{ include "%s.fullname" . }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ include "%s.fullname" . }}

  # Replica bounds
  minReplicaCount: 1
  maxReplicaCount: {{ .Values.autoscaling.maxReplicas }}

  # Scale to zero when no messages (set to 0 to enable)
  # minReplicaCount: 0

  # Cooldown periods
  cooldownPeriod: 300
  pollingInterval: 30

  # Advanced HPA behaviour passthrough
  advanced:
    restoreToOriginalReplicaCount: false
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
          policies:
            - type: Percent
              value: 100
              periodSeconds: 30

%s`, name, name, name, name, triggerBlock)
}

func helmKedaTriggerAuth(name string, opts models.KedaOpts) string {
	var secretRef string
	switch opts.Trigger {
	case "kafka":
		secretRef = fmt.Sprintf(`  secretTargetRef:
    # Reference the application secret (created by ESO/Vault/etc.)
    - parameter: sasl
      name: {{ include "%s.fullname" . }}-secret
      key: KAFKA_SASL_PASSWORD
    - parameter: username
      name: {{ include "%s.fullname" . }}-secret
      key: KAFKA_SASL_USERNAME
`, name, name)
	case "rabbitmq":
		secretRef = fmt.Sprintf(`  secretTargetRef:
    - parameter: host
      name: {{ include "%s.fullname" . }}-secret
      key: RABBITMQ_URL
`, name)
	case "redis":
		secretRef = fmt.Sprintf(`  secretTargetRef:
    - parameter: address
      name: {{ include "%s.fullname" . }}-secret
      key: REDIS_URL
    - parameter: password
      name: {{ include "%s.fullname" . }}-secret
      key: REDIS_PASSWORD
`, name, name)
	default:
		secretRef = fmt.Sprintf(`  secretTargetRef:
    - parameter: connection
      name: {{ include "%s.fullname" . }}-secret
      key: BROKER_URL
`, name)
	}

	return fmt.Sprintf(`# TriggerAuthentication — application-scoped broker credentials
# Credentials are sourced from the application Secret (managed by ESO/Vault).
# Never hardcode credentials here.
apiVersion: keda.sh/v1alpha1
kind: TriggerAuthentication
metadata:
  name: {{ include "%s.fullname" . }}-keda-auth
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
spec:
%s`, name, name, secretRef)
}

// ─────────────────────────────────────────────
// Vertical Pod Autoscaler
// ─────────────────────────────────────────────
func helmVPA(name string) string {
    return fmt.Sprintf(`# NOTE: VerticalPodAutoscaler requires a VPA controller installed in the cluster.
# Install and enable the VPA controller (or ensure your managed cluster provides it) before applying this manifest.
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: {{ include "%s.fullname" . }}-vpa
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ include "%s.fullname" . }}
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
      - containerName: {{ .Chart.Name }}
        minAllowed:
          cpu: 50m
          memory: 64Mi
        maxAllowed:
          cpu: 1000m
          memory: 512Mi
`, name, name, name)
}

func helmNotes(name string) string {
	return fmt.Sprintf(`CHART INSTALLED SUCCESSFULLY ✅
================================

Application : {{ include "%s.fullname" . }}
Namespace   : {{ .Release.Namespace }}
Version     : {{ .Chart.AppVersion }}

{{- if .Values.ingress.enabled }}
URL: https://{{ (first .Values.ingress.hosts).host }}/
{{- else }}
Port-forward (local):
  kubectl port-forward svc/{{ include "%s.fullname" . }} 8080:{{ default 80 .Values.service.port }} -n {{ .Release.Namespace }}
{{- end }}

QUICK COMMANDS
──────────────
Pod status:
  kubectl get pods -n {{ .Release.Namespace }} -l app.kubernetes.io/name={{ include "%s.name" . }}

Logs:
  kubectl logs -n {{ .Release.Namespace }} -l app.kubernetes.io/name={{ include "%s.name" . }} -f --tail=50

Describe:
  kubectl describe deployment/{{ include "%s.fullname" . }} -n {{ .Release.Namespace }}

SECURITY
────────
✔ Non-root execution (UID 65534)
✔ Read-only root filesystem
✔ All Linux capabilities dropped
✔ No privilege escalation
✔ Seccomp RuntimeDefault
✔ NetworkPolicy default deny-all
✔ RBAC least-privilege
`, name, name, name, name, name)
}

func helmIgnore() string {
	return `.DS_Store
.git/
.gitignore
.bzr/
.hg/
.svn/
.idea/
*.tmproj
.vscode/
tests/
.github/
.gitlab-ci.yml
docs/
CHANGELOG.md
*.md.bak
`
}

func helmReadme(name string, envs []string, keda models.KedaOpts, secrets models.SecretOpts) string {
  var b strings.Builder
  b.WriteString(fmt.Sprintf(`# %s — Helm Chart

Production-grade Helm chart targeting **Kubernetes 1.29 – 1.35+**.

## Security

| Control | Status |
|---|---|
| Non-root execution (UID 65534) | ✅ |
| Read-only root filesystem | ✅ |
| All capabilities dropped | ✅ |
| No privilege escalation | ✅ |
| Seccomp RuntimeDefault | ✅ |
| NetworkPolicy deny-all default | ✅ |
| RBAC least-privilege | ✅ |
| No automounted service account tokens | ✅ |

`, name))

  if keda.Enabled {
    b.WriteString(fmt.Sprintf("## KEDA (%s trigger)\n\nInstall KEDA first:\n```bash\nhelm repo add kedacore https://kedacore.github.io/charts\nhelm install keda kedacore/keda --namespace keda --create-namespace\n```\n\n", keda.Trigger))
  }
  if secrets.Provider == "external-secrets" {
    b.WriteString("## External Secrets Operator\n\n```bash\nhelm repo add external-secrets https://charts.external-secrets.io\nhelm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace\n```\n\n")
  }
  if secrets.Provider == "vault" {
    b.WriteString("## Vault Secrets Operator\n\n```bash\nhelm repo add hashicorp https://helm.releases.hashicorp.com\nhelm install vault-secrets-operator hashicorp/vault-secrets-operator -n vault-secrets-operator --create-namespace\n```\n\n")
  }

  b.WriteString(fmt.Sprintf("## Deploy\n\n### Lint\n```bash\nhelm lint ./%s -f values.yaml --strict\n```\n\n", name))

  // Helper to check presence
  envSet := toSet(envs)

  // Dev dry-run/deploy
  if envSet["dev"] {
    b.WriteString(fmt.Sprintf("### Dry-run (dev)\n```bash\nhelm upgrade --install %s ./%s \\\n+  --namespace %s-dev --create-namespace \\\n+  -f values.yaml -f values-dev.yaml \\\n+  --dry-run --debug\n```\n\n", name, name, name))

    b.WriteString(fmt.Sprintf("### Development\n```bash\nhelm upgrade --install %s ./%s \\\n+  --namespace %s-dev --create-namespace \\\n+  -f values.yaml -f values-dev.yaml\n```\n\n", name, name, name))
  }

  // Test
  if envSet["test"] {
    b.WriteString(fmt.Sprintf("### Test\n```bash\nhelm upgrade --install %s ./%s \\\n+  --namespace %s-test --create-namespace \\\n+  -f values.yaml -f values-test.yaml\n```\n\n", name, name, name))
  }

  // Staging
  if envSet["staging"] {
    b.WriteString(fmt.Sprintf("### Staging\n```bash\nhelm upgrade --install %s ./%s \\\n+  --namespace %s-staging --create-namespace \\\n+  -f values.yaml -f values-staging.yaml \\\n+  --wait --timeout 5m\n```\n\n", name, name, name))
  }

  // Production
  if envSet["prod"] {
    b.WriteString(fmt.Sprintf("### Production\n```bash\nhelm upgrade --install %s ./%s \\\n+  --namespace %s-prod --create-namespace \\\n+  -f values.yaml -f values-prod.yaml \\\n+  --atomic --cleanup-on-fail --timeout 5m \\\n+  --wait\n```\n\n", name, name, name))
  }

  return b.String()
}

// helpers
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func toSet(list []string) map[string]bool {
	m := make(map[string]bool)
	for _, v := range list {
		m[v] = true
	}
	return m
}
// ─────────────────────────────────────────────
// Istio — VirtualService
// ─────────────────────────────────────────────
func helmVirtualService(name string, istio models.IstiOpts) string {
	gateways := fmt.Sprintf(`- %s`, istio.GatewayName)
	if istio.MeshGateway {
		gateways += "\n  - mesh"
	}
	return fmt.Sprintf(`apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: {{ include "%s.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
spec:
  hosts:
  - "{{ include "%s.fullname" . }}"
  gateways:
  %s
  http:
  - match:
    - uri:
        prefix: /
    route:
    - destination:
        host: "{{ include "%s.fullname" . }}"
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
func helmDestinationRule(name string) string {
	return fmt.Sprintf(`apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: {{ include "%s.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
spec:
  host: "{{ include "%s.fullname" . }}"
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
func helmEnvoyFilter(name string) string {
	return fmt.Sprintf(`apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: {{ include "%s.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
spec:
  workloadSelector:
    labels:
      app.kubernetes.io/name: {{ include "%s.name" . }}
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
func helmAuthorizationPolicy(name string, istio models.IstiOpts) string {
	return fmt.Sprintf(`apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: {{ include "%s.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "%s.labels" . | nindent 4 }}
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: {{ include "%s.name" . }}
  action: %s
  rules:
  # Allow requests from same namespace
  - from:
    - source:
        namespaces:
        - {{ .Release.Namespace }}
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