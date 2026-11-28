{{/*
A generated ConfigMap's name: its base name and the suffix Kustomize's
configMapGenerator gives it, so that both renders name it alike while the
Kustomize trees still deploy the services that read it (#2908). The suffix
hashes the data alone: Kustomize's hasher looks the name up as one key,
"metadata/name", finds nothing, and hashes an empty name. Every value must
be a string, as an env file gives it.
Arguments: a dict with "name" and "data".
*/}}
{{- define "codewire.generatedName" -}}
{{- include "codewire.requireStrings" . }}
{{- $hash := dict "data" .data "kind" "ConfigMap" "name" "" | toJson | sha256sum | trunc 10 }}
{{- printf "%s-%s" .name ($hash | replace "0" "g" | replace "1" "h" | replace "3" "k" | replace "a" "m" | replace "e" "t") }}
{{- end }}

{{- define "codewire.configName" -}}
{{- include "codewire.generatedName" (dict "name" "codewire-config" "data" .Values.config) }}
{{- end }}

{{- define "codewire.dashboardPublicConfigName" -}}
{{- include "codewire.generatedName" (dict "name" "codewire-dashboard-public-config" "data" .Values.dashboardPublicConfig) }}
{{- end }}

{{/*
An image family's reference: its repository, then its digest when one is set,
or else its tag. Arguments: a dict with "family" and "images".
*/}}
{{- define "codewire.image" -}}
{{- $image := index .images .family }}
{{- $repository := required (printf "images.%s.repository is required" .family) $image.repository }}
{{- if $image.digest }}
{{- printf "%s@%s" $repository $image.digest }}
{{- else }}
{{- printf "%s:%s" $repository (required (printf "images.%s needs a digest or a tag" .family) $image.tag) }}
{{- end }}
{{- end }}

{{/*
The public edge's peers (edge.peers), for a network policy's `from`. Helm's
`required` passes an empty list, which would admit every peer, and an entry
whose selectors are empty matches every Pod or namespace, so each entry must
name the edge by a non-empty selector or an ipBlock.
Arguments: the root context.
*/}}
{{- define "codewire.edgePeers" -}}
{{- if not .Values.edge.peers }}
{{- fail "edge.peers must name the public edge" }}
{{- end }}
{{- range .Values.edge.peers }}
{{- $selects := or (dig "namespaceSelector" "matchLabels" nil .) (dig "namespaceSelector" "matchExpressions" nil .) (dig "podSelector" "matchLabels" nil .) (dig "podSelector" "matchExpressions" nil .) (dig "ipBlock" "cidr" nil .) }}
{{- if not $selects }}
{{- fail (printf "edge.peers entry %s selects every peer; name the public edge" (toJson .)) }}
{{- end }}
{{- end }}
{{- toYaml .Values.edge.peers }}
{{- end }}

{{/*
A service's selector labels, which its Pods carry. Arguments: the component.
*/}}
{{- define "codewire.selectorLabels" -}}
app.kubernetes.io/name: codewire
app.kubernetes.io/component: {{ . }}
{{- end }}

{{/*
The labels on a service's own objects: its selector labels and the part-of
label every Codewire object carries. Arguments: the component.
*/}}
{{- define "codewire.labels" -}}
{{ include "codewire.selectorLabels" . }}
app.kubernetes.io/part-of: codewire
{{- end }}

{{/*
The fields every Rust service's container shares: the services image, its
pull policy, codewire-config and the shared Secret and any further sources it
lists (extraEnvFrom), its own environment, resources, and a startup probe
when one is set.
Arguments: a dict with "root" (the root context) and "service" (its values).
*/}}
{{- define "codewire.serviceContainer" -}}
image: {{ include "codewire.image" (dict "family" "services" "images" .root.Values.images) }}
{{- with .service.imagePullPolicy }}
imagePullPolicy: {{ . }}
{{- end }}
envFrom:
  - configMapRef:
      name: {{ include "codewire.configName" .root }}
  - secretRef:
      name: {{ .root.Values.sharedSecret }}
  {{- with .service.extraEnvFrom }}
  {{- toYaml . | nindent 2 }}
  {{- end }}
env:
  {{- toYaml .service.env | nindent 2 }}
  {{- with .extraEnv }}
  {{- toYaml . | nindent 2 }}
  {{- end }}
resources:
  {{- toYaml .service.resources | nindent 2 }}
{{- with .service.startupProbe }}
startupProbe:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
The Pod-level fields every Rust service shares: its pull secrets, always
written, and its init containers when it has any.
Arguments: a dict with "root" and "service".
*/}}
{{- define "codewire.servicePod" -}}
imagePullSecrets: {{ toYaml .root.Values.imagePullSecrets | nindent 2 }}
{{- with .service.initContainers }}
initContainers:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
A network policy peer that selects Pods by their labels. Every peer the chart
builds from labels goes through here: an empty or null selector matches every
Pod in the namespace, so it is refused, whether or not the selected component
is rendered. With "namespace", the peer is those Pods in that namespace only,
by its immutable kubernetes.io/metadata.name, and an empty namespace is
refused too. Arguments: a dict with "labels", optionally "namespace", and
"from", the value they come from, for the refusal.
*/}}
{{- define "codewire.podPeer" -}}
{{- if not .labels }}
{{- fail (printf "%s is empty: a peer selecting no labels admits every Pod" .from) }}
{{- end }}
{{- if and (hasKey . "namespace") (not .namespace) }}
{{- fail (printf "%s is empty: the peer must name its namespace, or it selects the policy's own" .from) }}
{{- end }}
- podSelector:
    matchLabels:
      {{- toYaml .labels | nindent 6 }}
  {{- with .namespace }}
  namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: {{ . }}
  {{- end }}
{{- end }}

{{/*
A list of strings as a CEL list literal, for an admission policy's variable:
['a', 'b']. Arguments: the list.
*/}}
{{- define "codewire.celStrings" -}}
[{{ range $i, $s := . }}{{ if $i }}, {{ end }}'{{ $s }}'{{ end }}]
{{- end }}

{{/*
Refuses any value of a ConfigMap's data that is not a string, as an env file
gives every value. Renders nothing. Arguments: a dict with "name", for the
refusal, and "data".
*/}}
{{- define "codewire.requireStrings" -}}
{{- range $key, $value := .data }}
{{- if not (kindIs "string" $value) }}
{{- fail (printf "%s: %s must be a string; quote it" $.name $key) }}
{{- end }}
{{- end }}
{{- end }}

{{/*
RuntimeClass names as an admission policy's CEL list. Each is written into the
policy's expression, so each must be a DNS subdomain, as a RuntimeClass name
is, or '' for a Pod without runtimeClassName. Arguments: a dict with "names"
and "from", the value they come from, for the refusal.
*/}}
{{- define "codewire.runtimeClassesCel" -}}
{{- range .names }}
{{- if not (or (eq . "") (and (le (len .) 253) (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" .))) }}
{{- fail (printf "%s: %q is not a RuntimeClass name" $.from .) }}
{{- end }}
{{- end }}
{{- include "codewire.celStrings" .names }}
{{- end }}

{{/*
Standard Envoy Gateway response/request filters for public HTTPS routes:
strict HSTS and stripping caller-supplied trace context headers so traces start
at the edge (#5628, #5633).
*/}}
{{- define "codewire.gatewayEdgeFilters" -}}
- type: ResponseHeaderModifier
  responseHeaderModifier:
    set:
      - name: Strict-Transport-Security
        value: "max-age=31536000; includeSubDomains"
- type: RequestHeaderModifier
  requestHeaderModifier:
    remove: [traceparent, tracestate, baggage]
{{- end }}
