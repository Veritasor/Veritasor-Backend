{{- /*
helpers.tpl — reusable template functions for veritasor-backend
SPDX-License-Identifier: MIT
*/}}

{{- /*
veritasor.name — expand the chart name.
*/}}
{{- define "veritasor.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- /*
veritasor.fullname — fully qualified app name.
*/}}
{{- define "veritasor.fullname" -}}
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

{{- /*
veritasor.labels — standard Kubernetes labels.
*/}}
{{- define "veritasor.labels" -}}
helm.sh/chart: {{ include "veritasor.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "veritasor.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- /*
veritasor.selectorLabels — selector labels for Deployment etc.
*/}}
{{- define "veritasor.selectorLabels" -}}
app.kubernetes.io/name: {{ include "veritasor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- /*
veritasor.serviceAccountName — returns the service account name.
*/}}
{{- define "veritasor.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "veritasor.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- /*
veritasor.image — fully qualified image reference.
*/}}
{{- define "veritasor.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end }}
