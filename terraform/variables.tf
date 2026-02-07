variable "project_name" { type = string, default = "ccs6344" }

variable "aws_region" { type = string, default = "us-east-1" }

variable "vpc_cidr" { type = string, default = "10.10.0.0/16" }

variable "public_subnet_1_cidr"  { type = string, default = "10.10.1.0/24" }
variable "public_subnet_2_cidr"  { type = string, default = "10.10.2.0/24" }
variable "private_subnet_1_cidr" { type = string, default = "10.10.11.0/24" }
variable "private_subnet_2_cidr" { type = string, default = "10.10.12.0/24" }

variable "key_name" { type = string, default = "vockey" }

variable "app_instance_type" {
  type    = string
  default = "t2.micro"
}

variable "db_instance_type" {
  type    = string
  default = "t3.micro"
}

variable "instance_profile_name" {
  type        = string
  default     = "LabInstanceProfile"
  description = "Existing instance profile in Learner Lab (do not create IAM roles)."
}

variable "db_name" { type = string, default = "studentdb" }
variable "db_user" { type = string, default = "studentuser" }

variable "db_password" {
  type      = string
  sensitive = true
}

variable "acm_certificate_arn" {
  type        = string
  default     = ""
  description = "Optional ACM cert ARN for HTTPS on ALB. Leave empty to use HTTP only."
}

variable "admin_cidr" {
  type    = string
  default = "0.0.0.0/32"
}

variable "admin_ipv6_cidr" {
  type    = string
  default = "::/128"
}

# AMI: Amazon Linux 2023
variable "app_ami_ssm_parameter" {
  type    = string
  default = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# GitHub deploy settings
variable "github_repo_url" {
  type    = string
  default = "https://github.com/hazmananwar/CCS6344-T2530-Assignment-2.git"
}

variable "github_branch" {
  type    = string
  default = "main"
}

variable "app_entry_point" {
  type    = string
  default = "app.py"
}

variable "templates_dir" {
  type    = string
  default = "templates"
}

variable "static_dir" {
  type    = string
  default = "static"
}

variable "flask_secret_key" {
  type      = string
  sensitive = true
  default   = "CHANGE-ME-VERY-LONG-RANDOM-STRING"
}
