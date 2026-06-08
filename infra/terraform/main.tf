terraform {
  required_version = ">= 1.6"
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.30" }
    helm       = { source = "hashicorp/helm", version = "~> 2.13" }
  }
}

# Provider configuration is environment-specific; supply via backend + tfvars.
provider "kubernetes" {
  config_path = var.kubeconfig
}

provider "helm" {
  kubernetes {
    config_path = var.kubeconfig
  }
}

resource "kubernetes_namespace" "aegisflow" {
  metadata {
    name = var.namespace
    labels = {
      "pod-security.kubernetes.io/enforce" = "restricted"
      "istio-injection"                    = "enabled"
    }
  }
}

# Managed Postgres / Neo4j / Redis / Kafka are provisioned by cloud-specific
# modules (RDS/CloudSQL, Aura, ElastiCache, MSK). Referenced here as module
# placeholders so the root module composes the full platform.
module "data_stores" {
  source    = "./modules/data_stores"
  namespace = kubernetes_namespace.aegisflow.metadata[0].name
  region    = var.region
}
