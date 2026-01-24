{{/*
Expand the name of the chart.
*/}}
{{- define "wicket.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "wicket.fullname" -}}
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
{{- define "wicket.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "wicket.labels" -}}
helm.sh/chart: {{ include "wicket.chart" . }}
{{ include "wicket.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "wicket.selectorLabels" -}}
app.kubernetes.io/name: {{ include "wicket.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Controller name
*/}}
{{- define "wicket.controller.name" -}}
{{ include "wicket.fullname" . }}-controller
{{- end }}

{{/*
Controller labels
*/}}
{{- define "wicket.controller.labels" -}}
{{ include "wicket.labels" . }}
app.kubernetes.io/component: controller
{{- end }}

{{/*
Controller selector labels
*/}}
{{- define "wicket.controller.selectorLabels" -}}
{{ include "wicket.selectorLabels" . }}
app.kubernetes.io/component: controller
{{- end }}

{{/*
Proxy name
*/}}
{{- define "wicket.proxy.name" -}}
{{ include "wicket.fullname" . }}-proxy
{{- end }}

{{/*
Proxy labels
*/}}
{{- define "wicket.proxy.labels" -}}
{{ include "wicket.labels" . }}
app.kubernetes.io/component: proxy
{{- end }}

{{/*
Proxy selector labels
*/}}
{{- define "wicket.proxy.selectorLabels" -}}
{{ include "wicket.selectorLabels" . }}
app.kubernetes.io/component: proxy
{{- end }}

{{/*
Controller service account name
*/}}
{{- define "wicket.controller.serviceAccountName" -}}
{{- if .Values.controller.serviceAccount.create }}
{{- default (include "wicket.controller.name" .) .Values.controller.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.controller.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Proxy service account name
*/}}
{{- define "wicket.proxy.serviceAccountName" -}}
{{- if .Values.proxy.serviceAccount.create }}
{{- default (include "wicket.proxy.name" .) .Values.proxy.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.proxy.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Controller image
*/}}
{{- define "wicket.controller.image" -}}
{{ .Values.controller.image.repository }}:{{ .Values.controller.image.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
Proxy image
*/}}
{{- define "wicket.proxy.image" -}}
{{ .Values.proxy.image.repository }}:{{ .Values.proxy.image.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
Namespace
*/}}
{{- define "wicket.namespace" -}}
{{ .Values.namespace.name | default .Release.Namespace }}
{{- end }}
