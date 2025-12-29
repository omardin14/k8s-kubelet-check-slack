{{/*
Expand the name of the chart.
*/}}
{{- define "kubelet-check-slack.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "kubelet-check-slack.fullname" -}}
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
{{- define "kubelet-check-slack.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kubelet-check-slack.labels" -}}
helm.sh/chart: {{ include "kubelet-check-slack.chart" . }}
{{ include "kubelet-check-slack.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kubelet-check-slack.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kubelet-check-slack.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "kubelet-check-slack.serviceAccountName" -}}
{{- if .Values.rbac.serviceAccount.name }}
{{- .Values.rbac.serviceAccount.name }}
{{- else }}
{{- include "kubelet-check-slack.fullname" . }}
{{- end }}
{{- end }}

{{/*
Create the name of the cluster role
*/}}
{{- define "kubelet-check-slack.clusterRoleName" -}}
{{- if .Values.rbac.clusterRole.name }}
{{- .Values.rbac.clusterRole.name }}
{{- else }}
{{- include "kubelet-check-slack.fullname" . }}
{{- end }}
{{- end }}

{{/*
Create the name of the cluster role binding
*/}}
{{- define "kubelet-check-slack.clusterRoleBindingName" -}}
{{- if .Values.rbac.clusterRoleBinding.name }}
{{- .Values.rbac.clusterRoleBinding.name }}
{{- else }}
{{- include "kubelet-check-slack.fullname" . }}
{{- end }}
{{- end }}

{{/*
Create the name of the secret
*/}}
{{- define "kubelet-check-slack.secretName" -}}
{{- if kindIs "string" .Values.slack.token }}
{{- printf "%s-slack-credentials" (include "kubelet-check-slack.fullname" .) }}
{{- else }}
slack-credentials
{{- end }}
{{- end }}

{{/*
Get the namespace
*/}}
{{- define "kubelet-check-slack.namespace" -}}
{{- .Values.namespace.name }}
{{- end }}

