# Placeholder module: in each cloud this wraps the managed offerings
# (e.g. aws_db_instance for Postgres, aws_elasticache_cluster for Redis,
# aws_msk_cluster for Kafka, neo4j Aura via its provider). Kept abstract so the
# root module is cloud-agnostic and reviewable.

variable "namespace" { type = string }
variable "region" { type = string }

output "namespace" {
  value = var.namespace
}

output "region" {
  value = var.region
}
