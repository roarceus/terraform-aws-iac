variable "region" {
  description = "AWS region"
  type        = string
}

variable "vpc_cidr_block" {
  description = "CIDR block for the VPC"
  type        = string
}

variable "public_subnet_cidrs" {
  description = "List of CIDR blocks for public subnets"
  type        = list(string)
}

variable "private_subnet_cidrs" {
  description = "List of CIDR blocks for private subnets"
  type        = list(string)
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
}

variable "public_route_destination_cidr_block" {
  description = "Destination CIDR block for the public route table"
  type        = string
}

variable "environment" {
  description = "The environment for this VPC (dev, demo)"
  type        = string
}

variable "project_name" {
  description = "Project name for the resources"
  type        = string
}

# AWS EC2
variable "ami_id" {
  description = "AMI ID"
  type        = string
}

variable "instance_type" {
  description = "Type of EC2 instance"
  type        = string
}

variable "key_name" {
  description = "Name of key pair for EC2"
  type        = string
}

variable "volume_size" {
  description = "Instance volume size"
  type        = number
}

variable "volume_type" {
  description = "Instance volume type"
  type        = string
}

variable "app_port" {
  description = "Application port"
  type        = string
}

variable "launch_template_name" {
  description = "Name for launch template"
  type        = string
}

variable "asg_name" {
  description = "Name for auto scaling group"
  type        = string
}

variable "asg_desired_capacity" {
  description = "Application port"
  type        = number
}

variable "asg_max_size" {
  description = "Application port"
  type        = number
}

variable "asg_min_size" {
  description = "Application port"
  type        = number
}

variable "low_threshold" {
  description = "Application port"
  type        = string
}

variable "high_threshold" {
  description = "Application port"
  type        = string
}

variable "ipv4_cidr_blocks" {
  description = "IPv4 CIDR"
  type        = list(string)
}

variable "ipv6_cidr_blocks" {
  description = "IPv6 CIDR"
  type        = list(string)
}

variable "db_identifier" {
  description = "Database identifier"
  type        = string
}

variable "db_engine" {
  description = "Database engine"
  type        = string
}

variable "db_engine_version" {
  description = "Database version"
  type        = string
}

variable "db_instance_class" {
  description = "Database instance class"
  type        = string
}

variable "db_allocated_storage" {
  description = "Database allocated storage"
  type        = number
}

variable "db_name" {
  description = "Database name"
  type        = string
}

variable "db_user" {
  description = "Database user"
  type        = string
}

# variable "db_password" {
#   description = "Database password"
#   type        = string
# }

variable "db_port" {
  description = "Application port"
  type        = number
}

variable "hosted_zone_id" {
  description = "Route53 Hosted Zone ID"
  type        = string
}

variable "domain_name" {
  description = "Route53 Domain Name"
  type        = string
}

variable "record_type" {
  description = "Route53 Record Type"
  type        = string
}

variable "lambda_file_path" {
  description = "File path for Lambda function"
  type        = string
}

variable "SENDGRID_API_KEY" {
  description = "API Key for Sendgrid mailing service"
  type        = string
}

variable "sender_email" {
  description = "Email ID for sending emails"
  type        = string
}