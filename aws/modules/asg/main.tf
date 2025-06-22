resource "aws_security_group" "elasticsearch" {
  name_prefix = "${var.cluster_name}-es-"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 9200
    to_port         = 9200
    protocol        = "tcp"
    security_groups = [var.eks_security_group_id]
    description     = "ElasticSearch HTTP"
  }

  ingress {
    from_port       = 9300
    to_port         = 9300
    protocol        = "tcp"
    security_groups = [var.eks_security_group_id]
    description     = "ElasticSearch Transport"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-elasticsearch-sg"
  })
}

resource "aws_iam_role" "elasticsearch_instance" {
  name = "${var.cluster_name}-es-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "elasticsearch_instance" {
  name = "elasticsearch-instance-policy"
  role = aws_iam_role.elasticsearch_instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sts:GetCallerIdentity",
          "ec2:DescribeInstances",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Resource = "arn:aws:ssm:*:*:parameter/${var.cluster_name}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:UpdateInstanceInformation",
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetEncryptionConfiguration"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_managed_instance_core" {
  role       = aws_iam_role.elasticsearch_instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_launch_template" "elasticsearch" {
  name_prefix   = "${var.cluster_name}-es-"
  image_id      = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name

  vpc_security_group_ids = [aws_security_group.elasticsearch.id]

  iam_instance_profile {
    arn = aws_iam_instance_profile.elasticsearch.arn
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    echo "ElasticSearch instance started" > /tmp/startup.log

    # Update SSM agent (it's pre-installed on Amazon Linux 2)
    sudo yum install -y amazon-ssm-agent
    sudo systemctl enable amazon-ssm-agent
    sudo systemctl start amazon-ssm-agent

    # ElasticSearch installation will be handled separately
  EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name       = "${var.cluster_name}-elasticsearch"
      Type       = "elasticsearch"
      SSMManaged = "true"
    })
  }

  tags = var.tags
}

resource "aws_iam_instance_profile" "elasticsearch" {
  name = "${var.cluster_name}-es-instance-profile"
  role = aws_iam_role.elasticsearch_instance.name
}

resource "aws_autoscaling_group" "elasticsearch" {
  name_prefix         = "${var.cluster_name}-es-"
  vpc_zone_identifier = var.subnet_ids
  min_size            = var.min_size
  max_size            = var.max_size
  desired_capacity    = var.desired_capacity

  launch_template {
    id      = aws_launch_template.elasticsearch.id
    version = "$Latest"
  }

  health_check_type         = "EC2"
  health_check_grace_period = 300

  tag {
    key                 = "Name"
    value               = "${var.cluster_name}-elasticsearch"
    propagate_at_launch = true
  }

  tag {
    key                 = "Type"
    value               = "elasticsearch"
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = var.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
}