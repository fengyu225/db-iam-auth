variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where EKS will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for EKS cluster"
  type        = list(string)
}

variable "private_subnets" {
  description = "List of private subnet IDs for node groups"
  type        = list(string)
}

variable "kubernetes_version" {
  description = "Kubernetes version to use for the EKS cluster"
  type        = string
  default     = "1.32"
}

variable "node_instance_type" {
  description = "Instance type for EKS nodes"
  type        = string
  default     = "t3.xlarge"
}

variable "desired_capacity" {
  description = "Desired number of nodes"
  type        = number
  default     = 2
}

variable "min_size" {
  description = "Minimum number of nodes"
  type        = number
  default     = 1
}

variable "max_size" {
  description = "Maximum number of nodes"
  type        = number
  default     = 3
}

variable "ssh_key_name" {
  description = "SSH key name for node access"
  type        = string
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}