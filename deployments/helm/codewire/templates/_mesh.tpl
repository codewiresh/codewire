{{/*
The Mesh chart's templates (apps/cli/charts/codewire-mesh), kept verbatim as
named templates so the Codewire chart renders Mesh exactly as that chart does
(#2908). templates/mesh.yaml calls them with the context that chart's release
would give them; until slice 8 the two copies must change together, and
scripts/ci/tests/test-deploy-helm-chart.py fails on any difference.
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "codewire-mesh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "codewire-mesh.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "codewire-mesh.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "codewire-mesh.labels" -}}
helm.sh/chart: {{ include "codewire-mesh.chart" . }}
{{ include "codewire-mesh.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "codewire-mesh.selectorLabels" -}}
app.kubernetes.io/name: {{ include "codewire-mesh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "codewire-mesh.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "codewire-mesh.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the image tag to use.
*/}}
{{- define "codewire-mesh.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag }}
{{- end }}

{{/*
Return the full image reference to use. Digest takes precedence over tag.
*/}}
{{- define "codewire-mesh.imageRef" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository (trimPrefix "@" .Values.image.digest) -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (include "codewire-mesh.imageTag" .) -}}
{{- end -}}
{{- end }}

{{- define "codewire.mesh.serviceaccount" -}}
{{- if .Values.serviceAccount.create -}}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "codewire-mesh.serviceAccountName" . }}
  labels:
    {{- include "codewire-mesh.labels" . | nindent 4 }}
  {{- with .Values.serviceAccount.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
automountServiceAccountToken: false
{{- end }}
{{- end }}

{{- define "codewire.mesh.service-http" -}}
apiVersion: v1
kind: Service
metadata:
  name: {{ include "codewire-mesh.fullname" . }}-http
  labels:
    {{- include "codewire-mesh.labels" . | nindent 4 }}
spec:
  type: ClusterIP
  ports:
    - port: 8080
      targetPort: http
      protocol: TCP
      name: http
    {{- if .Values.mesh.derpVerifyPort }}
    - port: {{ .Values.mesh.derpVerifyPort }}
      targetPort: derp-verify
      protocol: TCP
      name: derp-verify
    {{- end }}
  selector:
    {{- include "codewire-mesh.selectorLabels" . | nindent 4 }}
{{- end }}

{{- define "codewire.mesh.retained-data-pvc" -}}
{{- /*
The claim Mesh's retired /data volume used. Nothing mounts it. It stays in the
chart, annotated keep, because dropping it would make Helm delete it, and the
clusters' deletion guard refuses that and fails the release (codewire#3542).
Once a release with keep is deployed in every environment, removing this
template leaves the claim in place; retiring the volume itself is a separate,
approved step.
*/ -}}
{{- with .Values.retainedDataClaim.size }}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ include "codewire-mesh.fullname" $ }}-data
  labels:
    {{- include "codewire-mesh.labels" $ | nindent 4 }}
  annotations:
    helm.sh/resource-policy: keep
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: {{ . }}
{{- end }}
{{- end }}

{{- define "codewire.mesh.deployment" -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "codewire-mesh.fullname" . }}
  labels:
      {{- include "codewire-mesh.labels" . | nindent 4 }}
{{- if and .Values.database.enabled (not .Values.meshAuthorization.url) }}
{{- fail "database-enabled Mesh requires meshAuthorization.url" }}
{{- end }}
{{- if and .Values.meshAuthorization.url (not .Values.meshAuthorization.hmacSecretRef.name) }}
{{- fail "meshAuthorization.url requires meshAuthorization.hmacSecretRef.name" }}
{{- end }}
{{- if and .Values.meshAuthorization.url (not (hasPrefix "https://" .Values.meshAuthorization.url)) }}
{{- fail "meshAuthorization.url must be https: orchestration's internal listener is TLS-only" }}
{{- end }}
{{- if ne (not (empty .Values.meshAuthorization.url)) (not (empty .Values.meshAuthorization.tlsRootsConfigMap)) }}
{{- fail "meshAuthorization.url and meshAuthorization.tlsRootsConfigMap must be set together" }}
{{- end }}
{{- if and .Values.nats.url (not .Values.nats.loginSecret) }}
{{- fail "nats.url requires nats.loginSecret: Mesh signs in to NATS only as its own user (codewire#3542)" }}
{{- end }}
{{- if and (gt (int .Values.replicaCount) 1) (not .Values.nats.url) }}
{{- fail "replicaCount above 1 requires nats.url: without NATS each Mesh replica keeps its own in-memory registry, so a second one would split the network (codewire#3542)" }}
{{- end }}
spec:
  replicas: {{ .Values.replicaCount }}
  {{- if .Values.nats.url }}
  # Replicas share the live registry through NATS: a new pod serves beside
  # the old one, which drains its sessions to the others as it stops.
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  {{- else }}
  # The live registry is in process memory, so two pods must never serve at
  # once: the old pod stops before the new one starts.
  strategy:
    type: Recreate
  {{- end }}
  selector:
    matchLabels:
      {{- include "codewire-mesh.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      {{- with .Values.podAnnotations }}
      annotations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      labels:
        {{- include "codewire-mesh.labels" . | nindent 8 }}
        {{- with .Values.podLabels }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
    spec:
      {{- with .Values.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      serviceAccountName: {{ include "codewire-mesh.serviceAccountName" . }}
      containers:
        - name: mesh
          image: "{{ include "codewire-mesh.imageRef" . }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          command: ["codewire-mesh"]
          args:
            - {{ printf "--base-url=%s" .Values.mesh.baseURL | quote }}
            - {{ printf "--listen=%s" .Values.mesh.listenAddr | quote }}
            {{- if .Values.mesh.derpURL }}
            - {{ printf "--derp-url=%s" .Values.mesh.derpURL | quote }}
            {{- end }}
          env:
            {{- if .Values.mesh.derpVerifyPort }}
            - name: CODEWIRE_MESH_DERP_VERIFY_ADDR
              value: {{ printf "0.0.0.0:%v" .Values.mesh.derpVerifyPort | quote }}
            {{- end }}
            {{- with .Values.stunServers }}
            - name: CODEWIRE_MESH_STUN_SERVERS
              value: {{ join "," . | quote }}
            {{- end }}
            {{- if .Values.nats.url }}
            - name: NATS_URL
              value: {{ .Values.nats.url | quote }}
            - name: NATS_KV_REPLICAS
              value: {{ .Values.nats.kvReplicas | quote }}
            {{- with .Values.nats.loginSecret }}
            - name: NATS_USER
              valueFrom:
                secretKeyRef:
                  name: {{ . }}
                  key: user
            - name: NATS_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: {{ . }}
                  key: password
            {{- end }}
            {{- end }}
            {{- if .Values.database.enabled }}
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: {{ .Values.database.secretName }}
                  key: {{ .Values.database.uriKey }}
            {{- end }}
            {{- if .Values.meshAuthorization.url }}
            # Hosted Mesh resolves product credentials only through the
            # cluster-local primary authorization service. This is an HMAC
            # sidecar credential, never a product bearer.
            - name: CODEWIRE_MESH_AUTHORIZATION_URL
              value: {{ .Values.meshAuthorization.url | quote }}
            - name: CODEWIRE_MESH_AUTHORIZATION_HMAC_SECRET
              valueFrom:
                secretKeyRef:
                  name: {{ .Values.meshAuthorization.hmacSecretRef.name }}
                  key: {{ .Values.meshAuthorization.hmacSecretRef.key }}
                  optional: {{ .Values.meshAuthorization.hmacSecretRef.optional | default false }}
            {{- if .Values.meshAuthorization.tlsRootsConfigMap }}
            - name: CODEWIRE_MESH_AUTHORIZATION_TLS_ROOTS_FILE
              value: /run/codewire-mesh-authorization-roots/ca.crt
            {{- end }}
            {{- end }}
          ports:
            - name: http
              containerPort: 8080
              protocol: TCP
            {{- if .Values.mesh.derpVerifyPort }}
            - name: derp-verify
              containerPort: {{ .Values.mesh.derpVerifyPort }}
              protocol: TCP
            {{- end }}
          livenessProbe:
            httpGet:
              path: /healthz
              port: http
            initialDelaySeconds: 10
            periodSeconds: 30
          # /readyz fails only once the process is stopping, so a draining
          # replica takes no new session. It never waits on NATS: through a
          # NATS outage each replica stays ready and serves its own view.
          readinessProbe:
            httpGet:
              path: /readyz
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
          {{- with .Values.resources }}
          resources:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          # Mesh writes no files: its state is in Postgres (or memory) and
          # NATS, and it only reads its mounted authorization roots.
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
            capabilities:
              drop:
                - ALL
            seccompProfile:
              type: RuntimeDefault
          {{- if .Values.meshAuthorization.tlsRootsConfigMap }}
          volumeMounts:
            - name: mesh-authorization-roots
              mountPath: /run/codewire-mesh-authorization-roots
              readOnly: true
          {{- end }}
      {{- if .Values.meshAuthorization.tlsRootsConfigMap }}
      volumes:
        - name: mesh-authorization-roots
          configMap:
            name: {{ .Values.meshAuthorization.tlsRootsConfigMap }}
      {{- end }}
      {{- with .Values.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- if .Values.affinity }}
      affinity:
        {{- toYaml .Values.affinity | nindent 8 }}
      {{- else if gt (int .Values.replicaCount) 1 }}
      # Replicas prefer separate nodes, so a node drain or reboot leaves one
      # serving; preferred, not required, so a short-handed cluster still
      # schedules both.
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                topologyKey: kubernetes.io/hostname
                labelSelector:
                  matchLabels:
                    {{- include "codewire-mesh.selectorLabels" . | nindent 20 }}
      {{- end }}
      {{- with .Values.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
{{- end }}

{{- define "codewire.mesh.pdb" -}}
{{- if gt (int .Values.replicaCount) 1 }}
# A voluntary disruption, such as a node drain, leaves one replica serving
# (codewire#3542).
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ include "codewire-mesh.fullname" . }}
  labels:
    {{- include "codewire-mesh.labels" . | nindent 4 }}
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      {{- include "codewire-mesh.selectorLabels" . | nindent 6 }}
{{- end }}
{{- end }}

{{- define "codewire.mesh.ingress" -}}
{{- if .Values.ingress.enabled -}}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "codewire-mesh.fullname" . }}
  labels:
    {{- include "codewire-mesh.labels" . | nindent 4 }}
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
    {{- range .Values.ingress.tls }}
    - hosts:
        {{- range .hosts }}
        - {{ . | quote }}
        {{- end }}
      secretName: {{ .secretName }}
    {{- end }}
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
                name: {{ include "codewire-mesh.fullname" $ }}-http
                port:
                  name: http
          {{- end }}
    {{- end }}
{{- end }}
{{- end }}

{{- define "codewire.mesh.coordinator-ingress" -}}
{{- if .Values.ingress.enabled -}}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "codewire-mesh.fullname" . }}-coordinator
  labels:
    {{- include "codewire-mesh.labels" . | nindent 4 }}
  annotations:
    nginx.ingress.kubernetes.io/use-regex: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "GRPC"
    nginx.ingress.kubernetes.io/proxy-request-buffering: "off"
    nginx.ingress.kubernetes.io/proxy-buffering: "off"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
spec:
  {{- if .Values.ingress.className }}
  ingressClassName: {{ .Values.ingress.className }}
  {{- end }}
  {{- if .Values.ingress.tls }}
  tls:
    {{- range .Values.ingress.tls }}
    - hosts:
        {{- range .hosts }}
        - {{ . | quote }}
        {{- end }}
      secretName: {{ .secretName }}
    {{- end }}
  {{- end }}
  rules:
    {{- range .Values.ingress.hosts }}
    - host: {{ .host | quote }}
      http:
        paths:
          - path: /codewire\.internal\.v1\.MeshCoordinatorService/
            pathType: ImplementationSpecific
            backend:
              service:
                name: {{ include "codewire-mesh.fullname" $ }}-http
                port:
                  name: http
    {{- end }}
{{- end }}
{{- end }}
