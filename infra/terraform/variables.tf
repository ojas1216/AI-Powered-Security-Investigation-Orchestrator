variable "kubeconfig" {
  type        = string
  default     = "~/.kube/config"
  description = "Path to kubeconfig for the target cluster."
}

variable "namespace" {
  type    = string
  default = "aegisflow"
}

variable "region" {
  type        = string
  default     = "us-east-1"
  description = "Cloud region for managed data stores."
}
