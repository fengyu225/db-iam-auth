output "workload_role_arns" {
  description = "ARNs of workload IAM roles"
  value = {
    for k, v in aws_iam_role.workload : k => v.arn
  }
}

output "database_role_arns" {
  description = "ARNs of database IAM roles"
  value = {
    for k, v in aws_iam_role.database : k => v.arn
  }
}

output "spire_oidc_provider_arn" {
  description = "ARN of the SPIRE OIDC provider"
  value       = aws_iam_openid_connect_provider.spire.arn
}

output "spire_oidc_provider_url" {
  description = "URL of the SPIRE OIDC provider"
  value       = aws_iam_openid_connect_provider.spire.url
}

output "workload_role_names" {
  description = "Names of workload IAM roles"
  value = {
    for k, v in aws_iam_role.workload : k => v.name
  }
}

output "database_role_names" {
  description = "Names of database IAM roles"
  value = {
    for k, v in aws_iam_role.database : k => v.name
  }
}

output "spire_server_role_arn" {
  description = "ARN of the SPIRE server IAM role"
  value       = aws_iam_role.spire_server.arn
}

output "spire_server_role_name" {
  description = "Name of the SPIRE server IAM role"
  value       = aws_iam_role.spire_server.name
}