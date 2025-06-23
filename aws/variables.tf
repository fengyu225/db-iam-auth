variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "db-iam-auth"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "eks_node_instance_type" {
  description = "Instance type for EKS nodes"
  type        = string
  default     = "t3.xlarge"
}

variable "eks_desired_capacity" {
  description = "Desired number of EKS nodes"
  type        = number
  default     = 1
}

variable "eks_min_size" {
  description = "Minimum number of EKS nodes"
  type        = number
  default     = 1
}

variable "eks_max_size" {
  description = "Maximum number of EKS nodes"
  type        = number
  default     = 1
}

variable "elasticsearch_instance_type" {
  description = "Instance type for ElasticSearch"
  type        = string
  default     = "t3.medium"
}

# IAM Variables
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
  default = {
    payment_service = {
      spiffe_id = "spiffe://example.org/ns/payment-service/sa/default"
      database_access = {
        elasticsearch = "payment-es-user"
        kafka         = "payment-kafka-user"
        cassandra     = "payment-cassandra-user"
      }
    }
    order_service = {
      spiffe_id = "spiffe://example.org/ns/order-service/sa/default"
      database_access = {
        elasticsearch = "order-es-user"
        cassandra     = "order-cassandra-user"
      }
    }
  }
}

variable "database_types" {
  description = "List of database types to create IAM roles for"
  type        = list(string)
  default     = ["elasticsearch", "kafka", "cassandra"]
}