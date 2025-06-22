output "autoscaling_group_id" {
  description = "ID of the Auto Scaling Group"
  value       = aws_autoscaling_group.elasticsearch.id
}

output "autoscaling_group_name" {
  description = "Name of the Auto Scaling Group"
  value       = aws_autoscaling_group.elasticsearch.name
}

output "autoscaling_group_arn" {
  description = "ARN of the Auto Scaling Group"
  value       = aws_autoscaling_group.elasticsearch.arn
}

output "security_group_id" {
  description = "ID of the ElasticSearch security group"
  value       = aws_security_group.elasticsearch.id
}

output "launch_template_id" {
  description = "ID of the launch template"
  value       = aws_launch_template.elasticsearch.id
}

output "launch_template_latest_version" {
  description = "Latest version of the launch template"
  value       = aws_launch_template.elasticsearch.latest_version
}

output "iam_role_arn" {
  description = "ARN of the ElasticSearch instance IAM role"
  value       = aws_iam_role.elasticsearch_instance.arn
}

output "iam_role_name" {
  description = "Name of the ElasticSearch instance IAM role"
  value       = aws_iam_role.elasticsearch_instance.name
}

output "instance_profile_arn" {
  description = "ARN of the ElasticSearch instance profile"
  value       = aws_iam_instance_profile.elasticsearch.arn
}

output "instance_profile_name" {
  description = "Name of the ElasticSearch instance profile"
  value       = aws_iam_instance_profile.elasticsearch.name
}