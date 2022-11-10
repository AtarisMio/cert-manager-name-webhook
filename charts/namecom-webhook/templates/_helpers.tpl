{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "namecom-webhook.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "namecom-webhook.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "namecom-webhook.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "namecom-webhook.selfSignedIssuer" -}}
{{ printf "%s-selfsign" (include "namecom-webhook.fullname" .) }}
{{- end -}}

{{- define "namecom-webhook.rootCAIssuer" -}}
{{ printf "%s-ca" (include "namecom-webhook.fullname" .) }}
{{- end -}}

{{- define "namecom-webhook.rootCACertificate" -}}
{{ printf "%s-ca" (include "namecom-webhook.fullname" .) }}
{{- end -}}

{{- define "namecom-webhook.servingCertificate" -}}
{{ printf "%s-webhook-tls" (include "namecom-webhook.fullname" .) }}
{{- end -}}
