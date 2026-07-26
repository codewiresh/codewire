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
