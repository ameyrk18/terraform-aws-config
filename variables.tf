variable "project" {
  description = "Project name"
  type        = "string"
}

variable "tags" {
  description = "Tags for aws config componenets"
  type        = "map"
  default     = {}
}

variable "aws_account_id" {
  description = "Project name"
  type        = "string"
}

variable "bucket_key_prefix" {
  description = "Project name"
  type        = "string"
}

variable "bucket_prefix" {
  description = "Project name"
  type        = "string"
}

//variable "aws_region" {}

variable "sns_topic_arn" {
  //default="arn:aws:sns:eu-west-1:xxxxxxx:test-topic"
  description = "SNA topic to send alerts"
  type        = "string"
}

