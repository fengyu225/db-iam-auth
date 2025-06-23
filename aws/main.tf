locals {
  cluster_name = "${var.project_name}-${var.environment}"
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name                                          = "${local.cluster_name}-vpc"
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
  })
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${local.cluster_name}-igw"
  })
}

resource "aws_subnet" "public" {
  count                   = length(var.availability_zones)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name                                          = "${local.cluster_name}-public-${count.index + 1}"
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                      = "1"
  })
}

resource "aws_subnet" "private" {
  count             = length(var.availability_zones)
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 100)
  availability_zone = var.availability_zones[count.index]

  tags = merge(local.common_tags, {
    Name                                          = "${local.cluster_name}-private-${count.index + 1}"
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = "1"
  })
}

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = merge(local.common_tags, {
    Name = "${local.cluster_name}-nat-eip"
  })
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = merge(local.common_tags, {
    Name = "${local.cluster_name}-nat"
  })

  depends_on = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = merge(local.common_tags, {
    Name = "${local.cluster_name}-public-rt"
  })
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = merge(local.common_tags, {
    Name = "${local.cluster_name}-private-rt"
  })
}

resource "aws_route_table_association" "public" {
  count          = length(var.availability_zones)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = length(var.availability_zones)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "tls_private_key" "main" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "main" {
  key_name   = "${local.cluster_name}-key"
  public_key = tls_private_key.main.public_key_openssh
}

resource "aws_s3_bucket" "spire_bundle" {
  bucket = "${local.cluster_name}-spire-bundle"

  tags = merge(local.common_tags, {
    Name = "${local.cluster_name}-spire-bundle"
  })
}

resource "aws_s3_bucket_public_access_block" "spire_bundle" {
  bucket = aws_s3_bucket.spire_bundle.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "spire_bundle" {
  bucket = aws_s3_bucket.spire_bundle.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.spire_bundle.arn}/*"
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.spire_bundle]
}

resource "aws_s3_bucket_cors_configuration" "spire_bundle" {
  bucket = aws_s3_bucket.spire_bundle.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "HEAD"]
    allowed_origins = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

resource "aws_s3_bucket_versioning" "spire_bundle" {
  bucket = aws_s3_bucket.spire_bundle.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_object" "openid_configuration" {
  bucket       = aws_s3_bucket.spire_bundle.id
  key          = ".well-known/openid-configuration"
  content_type = "application/json"

  content = jsonencode({
    issuer = "https://${aws_s3_bucket.spire_bundle.bucket}.s3.${data.aws_region.current.name}.amazonaws.com"
    jwks_uri = "https://${aws_s3_bucket.spire_bundle.bucket}.s3.${data.aws_region.current.name}.amazonaws.com/keys"
    response_types_supported = [
      "id_token"
    ]
    subject_types_supported = [
      "public"
    ]
    id_token_signing_alg_values_supported = [
      "RS256",
      "ES256"
    ]
    token_endpoint_auth_methods_supported = [
      "none"
    ]
    claims_supported = [
      "sub",
      "aud",
      "exp",
      "iat",
      "iss",
      "jti"
    ]
    scopes_supported = [
      "openid"
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.cluster_name}-openid-config"
  })

  depends_on = [
    aws_s3_bucket_policy.spire_bundle,
    aws_s3_bucket_cors_configuration.spire_bundle
  ]
}

module "eks" {
  source = "./modules/eks"

  cluster_name    = local.cluster_name
  vpc_id          = aws_vpc.main.id
  subnet_ids      = concat(aws_subnet.public[*].id, aws_subnet.private[*].id)
  private_subnets = aws_subnet.private[*].id

  node_instance_type = var.eks_node_instance_type
  desired_capacity   = var.eks_desired_capacity
  min_size           = var.eks_min_size
  max_size           = var.eks_max_size

  ssh_key_name = aws_key_pair.main.key_name

  tags = local.common_tags
}

module "iam" {
  source = "./modules/iam"

  cluster_name           = local.cluster_name
  oidc_provider_arn      = module.eks.oidc_provider_arn
  account_id             = data.aws_caller_identity.current.account_id
  region                 = data.aws_region.current.name
  spire_bundle_s3_bucket = aws_s3_bucket.spire_bundle.bucket

  workload_configs = var.workload_configs
  database_types   = var.database_types

  tags = local.common_tags
}

module "asg" {
  source = "./modules/asg"

  cluster_name  = local.cluster_name
  vpc_id        = aws_vpc.main.id
  subnet_ids    = aws_subnet.private[*].id
  instance_type = var.elasticsearch_instance_type
  ami_id        = data.aws_ami.amazon_linux_2.id
  key_name      = aws_key_pair.main.key_name

  eks_security_group_id = module.eks.node_security_group_id

  tags = local.common_tags
}