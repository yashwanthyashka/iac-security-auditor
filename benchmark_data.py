"""Built-in Terraform benchmark tasks for the IaC Security Auditor environment."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ExpectedFinding:
    issue_type: str
    resource: str
    severity: str
    explanation_keywords: tuple[str, ...]
    remediation_keywords: tuple[str, ...]


@dataclass(frozen=True)
class AuditTask:
    task_id: str
    title: str
    difficulty: str
    terraform_config: str
    findings: tuple[ExpectedFinding, ...]
    attack_path_keywords: tuple[str, ...] = ()
    allowed_issue_types: tuple[str, ...] = field(
        default_factory=lambda: (
            "public_ingress",
            "public_rds_access",
            "public_s3_read",
            "missing_encryption",
            "plaintext_secret",
            "overprivileged_iam",
            "imds_v1_enabled",
        )
    )


TASKS: tuple[AuditTask, ...] = (
    AuditTask(
        task_id="easy_s3_public",
        title="Public analytics bucket with no encryption",
        difficulty="easy",
        terraform_config="""
resource "aws_s3_bucket" "analytics_exports" {
  bucket = "company-analytics-exports"
}

resource "aws_s3_bucket_public_access_block" "analytics_exports" {
  bucket                  = aws_s3_bucket.analytics_exports.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "analytics_exports" {
  bucket = aws_s3_bucket.analytics_exports.id
  acl    = "public-read"
}
""".strip(),
        findings=(
            ExpectedFinding(
                issue_type="public_s3_read",
                resource="aws_s3_bucket.analytics_exports",
                severity="high",
                explanation_keywords=("public", "bucket", "internet", "read"),
                remediation_keywords=("private", "public access block", "acl"),
            ),
            ExpectedFinding(
                issue_type="missing_encryption",
                resource="aws_s3_bucket.analytics_exports",
                severity="medium",
                explanation_keywords=("encryption", "at rest", "sse"),
                remediation_keywords=("server_side_encryption_configuration", "kms", "aes256"),
            ),
        ),
    ),
    AuditTask(
        task_id="medium_rds_exposure",
        title="Publicly reachable Postgres with hardcoded password",
        difficulty="medium",
        terraform_config="""
resource "aws_security_group" "db_sg" {
  name = "db-sg"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "customer_db" {
  identifier          = "customer-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  username            = "app_admin"
  password            = "Welcome123!"
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  skip_final_snapshot = true
}
""".strip(),
        findings=(
            ExpectedFinding(
                issue_type="public_ingress",
                resource="aws_security_group.db_sg",
                severity="high",
                explanation_keywords=("5432", "0.0.0.0/0", "internet", "database"),
                remediation_keywords=("restricted cidr", "private subnet", "trusted"),
            ),
            ExpectedFinding(
                issue_type="public_rds_access",
                resource="aws_db_instance.customer_db",
                severity="critical",
                explanation_keywords=("publicly_accessible", "database", "internet"),
                remediation_keywords=("publicly_accessible = false", "private", "subnet"),
            ),
            ExpectedFinding(
                issue_type="plaintext_secret",
                resource="aws_db_instance.customer_db",
                severity="high",
                explanation_keywords=("hardcoded", "password", "plaintext", "secret"),
                remediation_keywords=("secrets manager", "ssm", "variable"),
            ),
        ),
    ),
    AuditTask(
        task_id="medium_ec2_role",
        title="Internet-facing bastion with admin IAM role",
        difficulty="medium",
        terraform_config="""
resource "aws_security_group" "bastion_sg" {
  name = "bastion-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "bastion_role" {
  name = "bastion-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "bastion_admin" {
  name = "bastion-admin"
  role = aws_iam_role.bastion_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
""".strip(),
        findings=(
            ExpectedFinding(
                issue_type="public_ingress",
                resource="aws_security_group.bastion_sg",
                severity="high",
                explanation_keywords=("ssh", "22", "0.0.0.0/0", "internet"),
                remediation_keywords=("restricted cidr", "vpn", "bastion"),
            ),
            ExpectedFinding(
                issue_type="overprivileged_iam",
                resource="aws_iam_role_policy.bastion_admin",
                severity="critical",
                explanation_keywords=("action", "*", "resource", "*", "admin"),
                remediation_keywords=("least privilege", "scoped", "specific actions"),
            ),
        ),
    ),
    AuditTask(
        task_id="hard_imds_chain",
        title="Attack-chain task: public app server to sensitive backups",
        difficulty="hard",
        terraform_config="""
resource "aws_security_group" "app_sg" {
  name = "app-sg"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "app_role" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "backup_read" {
  name = "backup-read"
  role = aws_iam_role.app_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [
        "arn:aws:s3:::prod-db-backups",
        "arn:aws:s3:::prod-db-backups/*"
      ]
    }]
  })
}

resource "aws_instance" "app" {
  ami                    = "ami-12345678"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.app_sg.id]
  iam_instance_profile   = aws_iam_role.app_role.name

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }
}
""".strip(),
        findings=(
            ExpectedFinding(
                issue_type="public_ingress",
                resource="aws_security_group.app_sg",
                severity="medium",
                explanation_keywords=("80", "0.0.0.0/0", "internet", "web"),
                remediation_keywords=("waf", "trusted cidr", "load balancer"),
            ),
            ExpectedFinding(
                issue_type="imds_v1_enabled",
                resource="aws_instance.app",
                severity="high",
                explanation_keywords=("http_tokens", "optional", "imdsv1", "metadata"),
                remediation_keywords=("required", "imdsv2", "metadata_options"),
            ),
            ExpectedFinding(
                issue_type="overprivileged_iam",
                resource="aws_iam_role_policy.backup_read",
                severity="high",
                explanation_keywords=("backup", "s3", "sensitive", "credentials"),
                remediation_keywords=("least privilege", "scope", "bucket"),
            ),
        ),
        attack_path_keywords=(
            "internet",
            "app",
            "metadata",
            "credentials",
            "s3",
            "backup",
        ),
    ),
)


TASK_INDEX = {task.task_id: task for task in TASKS}
