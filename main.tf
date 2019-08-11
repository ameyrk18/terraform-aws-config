locals {
  bucket_prefix = "${var.bucket_prefix}"
  bucket_key_prefix = "${var.bucket_key_prefix}"
  aws_account_id = "${var.aws_account_id}"
  sns_topic_arn = "${var.sns_topic_arn}"
  default_tags = {
    Description = "Managed by terraform"
    Project     = "${var.project}"
  }
}


# -----------------------------------------------------------
# set up a role for the Configuration Recorder to use
# -----------------------------------------------------------
resource "aws_iam_role" "config" {
  name = "config-${var.aws_account_id}"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "config_policy" {
  name = "config-policy-${var.aws_account_id}"
  role = "${aws_iam_role.config.id}"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "application-autoscaling:DescribeScalableTargets",
                "application-autoscaling:DescribeScalingPolicies",
                "autoscaling:DescribeAutoScalingGroups",
                "autoscaling:DescribeLaunchConfigurations",
                "autoscaling:DescribeLifecycleHooks",
                "autoscaling:DescribePolicies",
                "autoscaling:DescribeScheduledActions",
                "autoscaling:DescribeTags",
                "cloudfront:ListTagsForResource",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetEventSelectors",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:ListTags",
                "cloudwatch:DescribeAlarms",
                "codepipeline:GetPipeline",
                "codepipeline:GetPipelineState",
                "codepipeline:ListPipelines",
                "config:BatchGet*",
                "config:Describe*",
                "config:Get*",
                "config:List*",
                "config:Put*",
                "config:Select*",
                "dynamodb:DescribeContinuousBackups",
                "dynamodb:DescribeLimits",
                "dynamodb:DescribeTable",
                "dynamodb:ListTables",
                "dynamodb:ListTagsOfResource",
                "ec2:Describe*",
                "ec2:DescribeSnapshots",
                "elasticfilesystem:DescribeFileSystems",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "elasticloadbalancing:DescribeLoadBalancerPolicies",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeTags",
                "elasticmapreduce:DescribeCluster",
                "elasticmapreduce:DescribeSecurityConfiguration",
                "elasticmapreduce:ListClusters",
                "es:DescribeElasticsearchDomains",
                "es:ListDomainNames",
                "guardduty:GetDetector",
                "guardduty:GetMasterAccount",
                "guardduty:ListDetectors",
                "iam:GenerateCredentialReport",
                "iam:GetAccountAuthorizationDetails",
                "iam:GetAccountPasswordPolicy",
                "iam:GetAccountSummary",
                "iam:GetCredentialReport",
                "iam:GetGroup",
                "iam:GetGroupPolicy",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetRole",
                "iam:GetRolePolicy",
                "iam:GetUser",
                "iam:GetUserPolicy",
                "iam:ListAttachedGroupPolicies",
                "iam:ListAttachedRolePolicies",
                "iam:ListAttachedUserPolicies",
                "iam:ListEntitiesForPolicy",
                "iam:ListGroupPolicies",
                "iam:ListGroupsForUser",
                "iam:ListInstanceProfilesForRole",
                "iam:ListPolicyVersions",
                "iam:ListRolePolicies",
                "iam:ListUserPolicies",
                "iam:ListVirtualMFADevices",
                "kms:DescribeKey",
                "kms:GetKeyRotationStatus",
                "kms:ListKeys",
                "lambda:GetAlias",
                "lambda:GetFunction",
                "lambda:GetPolicy",
                "lambda:ListAliases",
                "lambda:ListFunctions",
                "logs:DescribeLogGroups",
                "rds:DescribeDBClusters",
                "rds:DescribeDBInstances",
                "rds:DescribeDBSecurityGroups",
                "rds:DescribeDBSnapshotAttributes",
                "rds:DescribeDBSnapshots",
                "rds:DescribeDBSubnetGroups",
                "rds:DescribeEventSubscriptions",
                "rds:ListTagsForResource",
                "redshift:DescribeClusterParameterGroups",
                "redshift:DescribeClusterParameters",
                "redshift:DescribeClusterSecurityGroups",
                "redshift:DescribeClusterSnapshots",
                "redshift:DescribeClusterSubnetGroups",
                "redshift:DescribeClusters",
                "redshift:DescribeEventSubscriptions",
                "redshift:DescribeLoggingStatus",
                "s3:GetAccelerateConfiguration",
                "s3:GetAccountPublicAccessBlock",
                "s3:GetBucketAcl",
                "s3:GetBucketCORS",
                "s3:GetBucketLocation",
                "s3:GetBucketLogging",
                "s3:GetBucketNotification",
                "s3:GetBucketObjectLockConfiguration",
                "s3:GetBucketPolicy",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketRequestPayment",
                "s3:GetBucketTagging",
                "s3:GetBucketVersioning",
                "s3:GetBucketWebsite",
                "s3:GetEncryptionConfiguration",
                "s3:GetLifecycleConfiguration",
                "s3:GetObject",
                "s3:GetReplicationConfiguration",
                "s3:ListAllMyBuckets",
                "s3:ListBucket",
                "s3:PutObject",
                "shield:DescribeDRTAccess",
                "shield:DescribeProtection",
                "shield:DescribeSubscription",
                "sns:ListSubscriptions",
                "sns:PutObject",
                "sns:GetBucketAcl",
                "sns:Publish",
                "ssm:DescribeAutomationExecutions",
                "ssm:DescribeDocument",
                "ssm:GetAutomationExecution",
                "ssm:GetDocument",
                "waf-regional:GetWebACL",
                "waf-regional:GetWebACLForResource"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}



# -----------------------------------------------------------
# set up a bucket for the Configuration Recorder to write to
# -----------------------------------------------------------
resource "aws_s3_bucket" "config" {
  bucket_prefix = "${var.bucket_prefix}"
  acl           = "private"
//  region        = "${var.aws_region}"

  versioning {
    enabled = true
  }

  lifecycle {
    prevent_destroy = true
  }

  logging {
    target_bucket = "${var.bucket_prefix}"
    target_prefix = "access_log/"
  }


  lifecycle_rule {
    enabled = true
    prefix  = "${var.bucket_key_prefix}-/"

    expiration {
      days = 90
    }


  }

  tags = "${merge(map("Name","Config Bucket"), var.tags)}"
}

resource "aws_s3_bucket_policy" "config_bucket_policy" {
  bucket = "${aws_s3_bucket.config.id}"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Allow bucket ACL check",
      "Effect": "Allow",
      "Principal": {
        "Service": [
         "config.amazonaws.com"
        ]
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "${aws_s3_bucket.config.arn}",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "true"
        }
      }
    },
    {
      "Sid": "Allow bucket write",
      "Effect": "Allow",
      "Principal": {
        "Service": [
         "config.amazonaws.com"
        ]
      },
      "Action": "s3:PutObject",
      "Resource": "${aws_s3_bucket.config.arn}/${var.bucket_key_prefix}/AWSLogs/${var.aws_account_id}/Config/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        },
        "Bool": {
          "aws:SecureTransport": "true"
        }
      }
    },
    {
      "Sid": "Require SSL",
      "Effect": "Deny",
      "Principal": {
        "AWS": "*"
      },
      "Action": "s3:*",
      "Resource": "${aws_s3_bucket.config.arn}/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
POLICY
}

# -----------------------------------------------------------
# set up the  Config Recorder
# -----------------------------------------------------------

resource "aws_config_configuration_recorder" "config" {
  name     = "config-recorder-role"
  role_arn = "${aws_iam_role.config.arn}"

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "config" {
  name           = "config-recorder-role"
  s3_bucket_name = "${aws_s3_bucket.config.bucket}"
  s3_key_prefix  = "${var.bucket_key_prefix}"
  sns_topic_arn  = "${var.sns_topic_arn}"

  snapshot_delivery_properties {
    delivery_frequency = "Three_Hours"
  }

  depends_on = ["aws_config_configuration_recorder.config"]
}

resource "aws_config_configuration_recorder_status" "config" {
  name       = "${aws_config_configuration_recorder.config.name}"
  is_enabled = true

  depends_on = ["aws_config_delivery_channel.config"]
}

# -----------------------------------------------------------
# set up the Config Recorder rules
# see https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html
# -----------------------------------------------------------
resource "aws_config_config_rule" "instances_in_vpc" {
  name = "instances_in_vpc"

  source {
    owner             = "AWS"
    source_identifier = "INSTANCES_IN_VPC"
  }

  depends_on = ["aws_config_configuration_recorder.config"]
}

resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  name = "s3_bucket_public_read_prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = ["aws_config_configuration_recorder.config"]
}

resource "aws_config_config_rule" "s3_bucket_public_write_prohibited" {
  name = "s3_bucket_public_write_prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  depends_on = ["aws_config_configuration_recorder.config"]
}