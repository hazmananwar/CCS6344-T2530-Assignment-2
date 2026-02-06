resource "aws_launch_template" "app" {
  name_prefix   = "student-portal-lt-"
  image_id      = var.ami_id
  instance_type = var.instance_type

  # FIXED: Use the pre-existing Academy Role
  iam_instance_profile {
    name = "LabInstanceProfile"
  }

  vpc_security_group_ids = [aws_security_group.app_sg.id]

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    flask_secret   = var.flask_secret
    db_host        = aws_db_instance.default.address
    db_name        = var.db_name
    db_user        = var.db_username
    db_pass        = var.db_password
    db_port        = 3306
    phone_enc_key  = var.phone_enc_key
    app_port       = var.app_port
  }))
}

resource "aws_autoscaling_group" "app" {
  name                = "student-portal-asg"
  vpc_zone_identifier = aws_subnet.private_app[*].id
  target_group_arns   = [aws_lb_target_group.main.arn]
  min_size            = var.asg_min
  max_size            = var.asg_max
  desired_capacity    = var.asg_desired
  health_check_type   = "ELB"
  health_check_grace_period = 120

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "student-portal-app"
    propagate_at_launch = true
  }
}
