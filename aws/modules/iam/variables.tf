variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "oidc_provider_arn" {
  description = "ARN of the EKS OIDC provider"
  type        = string
}

variable "account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
}

variable "spire_bundle_s3_bucket" {
  description = "S3 bucket name for SPIRE bundle storage"
  type        = string
}

variable "workload_configs" {
  description = "Configuration for workload IAM roles"
  type = map(object({
    spiffe_id = string
    database_access = object({
      elasticsearch = optional(string)
      kafka         = optional(string)
      cassandra     = optional(string)
    })
  }))
}

variable "database_types" {
  description = "List of database types to create IAM roles for"
  type        = list(string)
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}