variable "region" {
  description = "AWS Region"
  default     = "us-east-1"
}

variable "vpc_cidr" {
  default = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_app_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.11.0/24", "10.0.12.0/24"]
}

variable "private_db_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.21.0/24", "10.0.22.0/24"]
}

variable "app_port" {
  default = 5000
}

variable "acm_cert_arn" {
  description = "ARN of the ACM certificate for the ALB"
  # Replace this default with your actual ARN or pass it via -var
  default     = "arn:aws:acm:us-east-1:123456789012:certificate/PLACEHOLDER" 
}

variable "ami_id" {
  description = "Amazon Linux 2023 AMI ID"
  # You should dynamically look this up or set a default for your region
  default     = "ami-0230bd60aa48260c6" # Example AL2023 for us-east-1
}

variable "instance_type" {
  default = "t3.micro"
}

variable "asg_desired" { default = 1 }
variable "asg_min" { default = 1 }
variable "asg_max" { default = 2 }

# Secrets
variable "flask_secret" {
  sensitive = true
  default   = "change-me"
}

variable "phone_enc_key" {
  sensitive = true
  default   = "change-me-phone-key"
}

variable "db_name" { default = "StudentProjectDB" }
variable "db_username" { default = "admin" }
variable "db_password" {
  sensitive = true
  default   = "changeMe123!" 
}

variable "db_instance_class" { default = "db.t3.micro" }
variable "db_allocated_storage" { default = 20 }
variable "multi_az" { default = false }
