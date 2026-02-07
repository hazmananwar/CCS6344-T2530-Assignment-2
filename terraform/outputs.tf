output "vpc_id" {
  value = aws_vpc.this.id
}

output "alb_dns_name" {
  value = aws_lb.this.dns_name
}

output "alb_url" {
  value = length(trim(var.acm_certificate_arn)) > 0 ? "https://${aws_lb.this.dns_name}" : "http://${aws_lb.this.dns_name}"
}

output "app_instance_id" {
  value = aws_instance.app.id
}

output "db_instance_id" {
  value = aws_instance.db.id
}

output "db_private_ip" {
  value = aws_instance.db.private_ip
}

output "app_bucket_name" {
  value = aws_s3_bucket.app.bucket
}

output "cloudtrail_bucket_name" {
  value = aws_s3_bucket.trail.bucket
}

output "cloudtrail_name" {
  value = aws_cloudtrail.this.name
}
