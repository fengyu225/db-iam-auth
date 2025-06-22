# Cluster Outputs
output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks.cluster_endpoint
}

output "cluster_name" {
  description = "Name of the EKS cluster"
  value       = module.eks.cluster_name
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = module.eks.cluster_security_group_id
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = module.eks.cluster_certificate_authority_data
  sensitive   = true
}

# Network Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of private subnets"
  value       = aws_subnet.private[*].id
}

# ElasticSearch Outputs
output "elasticsearch_asg_name" {
  description = "Name of the ElasticSearch Auto Scaling Group"
  value       = module.asg.autoscaling_group_name
}

output "elasticsearch_security_group_id" {
  description = "Security group ID for ElasticSearch"
  value       = module.asg.security_group_id
}

# IAM Outputs
output "workload_role_arns" {
  description = "ARNs of workload IAM roles"
  value       = module.iam.workload_role_arns
}

output "database_role_arns" {
  description = "ARNs of database IAM roles"
  value       = module.iam.database_role_arns
}

output "spire_oidc_provider_arn" {
  description = "ARN of the SPIRE OIDC provider"
  value       = module.iam.spire_oidc_provider_arn
}

output "spire_oidc_provider_url" {
  description = "URL of the SPIRE OIDC provider"
  value       = module.iam.spire_oidc_provider_url
}

output "spire_server_role_arn" {
  description = "ARN of the SPIRE server IAM role"
  value       = module.iam.spire_server_role_arn
}

# S3 Bucket Outputs
output "spire_bundle_s3_bucket" {
  description = "S3 bucket name for SPIRE bundle storage"
  value       = aws_s3_bucket.spire_bundle.bucket
}

output "spire_bundle_s3_bucket_url" {
  description = "S3 bucket URL for SPIRE bundle storage"
  value       = "https://${aws_s3_bucket.spire_bundle.bucket}.s3.amazonaws.com"
}

# SSH Key Output
output "private_key_pem" {
  description = "Private key for SSH access to instances"
  value       = tls_private_key.main.private_key_pem
  sensitive   = true
}

# Account Information
output "aws_region" {
  description = "AWS region"
  value       = var.aws_region
}

output "aws_account_id" {
  description = "AWS Account ID"
  value       = data.aws_caller_identity.current.account_id
}