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
{{- range $key, $value := .data }}
{{- if not (kindIs "string" $value) }}
{{- fail (printf "%s: %s must be a string; quote it" $.name $key) }}
{{- end }}
{{- end }}
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
