output "alb_dns_name" {
  value = aws_lb.main.dns_name
}

output "db_endpoint" {
  value = aws_db_instance.default.address
}

output "asg_name" {
  value = aws_autoscaling_group.app.name
}
