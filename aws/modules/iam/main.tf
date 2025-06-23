resource "aws_iam_openid_connect_provider" "spire" {
  url = "https://${var.spire_bundle_s3_bucket}.s3.${var.region}.amazonaws.com"

  client_id_list = [
    "sts.amazonaws.com"
  ]

  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"]

  tags = var.tags
}

resource "aws_iam_role" "workload" {
  for_each = var.workload_configs

  name = "${var.cluster_name}-${replace(each.key, "_", "-")}-workload"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.spire.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${replace(aws_iam_openid_connect_provider.spire.url, "https://", "")}:aud" = "sts.amazonaws.com"
          "${replace(aws_iam_openid_connect_provider.spire.url, "https://", "")}:sub" = each.value.spiffe_id
        }
      }
    }]
  })

  tags = merge(var.tags, {
    dbTypes = join(":", [
      for db, user in each.value.database_access : db if user != null
    ])
    esUser        = try(each.value.database_access.elasticsearch, "")
    kafkaUser     = try(each.value.database_access.kafka, "")
    cassandraUser = try(each.value.database_access.cassandra, "")
  })
}

resource "aws_iam_role" "database" {
  for_each = toset(var.database_types)

  name                 = "${var.cluster_name}-${each.key}-db-role"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = var.account_id
      }
      Action    = "sts:AssumeRole"
      Condition = local.database_assume_conditions[each.key]
    }]
  })

  tags = merge(var.tags, {
    DatabaseType = each.key
  })
}

# IAM role for SPIRE server to write bundles to S3
resource "aws_iam_role" "spire_server" {
  name = "${var.cluster_name}-spire-server"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = var.oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "spire_server" {
  name = "spire-bundle-s3-policy"
  role = aws_iam_role.spire_server.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:DeleteObject"
        ]
        Resource = "arn:aws:s3:::${var.spire_bundle_s3_bucket}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = "arn:aws:s3:::${var.spire_bundle_s3_bucket}"
      }
    ]
  })
}

locals {
  database_assume_conditions = {
    elasticsearch = {
      StringEquals = {
        "sts:RoleSessionName" = "$${aws:PrincipalTag/esUser}"
      }
      "ForAnyValue:StringLike" = {
        "aws:PrincipalTag/dbTypes" = ["*elasticsearch*", "*es*"]
      }
      StringNotEquals = {
        "aws:PrincipalTag/esUser" = ""
      }
    }
    kafka = {
      StringEquals = {
        "sts:RoleSessionName" = "$${aws:PrincipalTag/kafkaUser}"
      }
      "ForAnyValue:StringLike" = {
        "aws:PrincipalTag/dbTypes" = ["*kafka*"]
      }
      StringNotEquals = {
        "aws:PrincipalTag/kafkaUser" = ""
      }
    }
    cassandra = {
      StringEquals = {
        "sts:RoleSessionName" = "$${aws:PrincipalTag/cassandraUser}"
      }
      "ForAnyValue:StringLike" = {
        "aws:PrincipalTag/dbTypes" = ["*cassandra*"]
      }
      StringNotEquals = {
        "aws:PrincipalTag/cassandraUser" = ""
      }
    }
  }
}

resource "aws_iam_role_policy" "workload_assume_db_roles" {
  for_each = var.workload_configs

  name = "assume-database-roles"
  role = aws_iam_role.workload[each.key].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Resource = [
        for db_role in aws_iam_role.database : db_role.arn
      ]
    }]
  })
}

resource "aws_iam_role_policy" "database_get_caller_identity" {
  for_each = toset(var.database_types)

  name = "get-caller-identity"
  role = aws_iam_role.database[each.key].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:GetCallerIdentity"
      Resource = "*"
    }]
  })
}