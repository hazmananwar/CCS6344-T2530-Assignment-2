resource "aws_db_subnet_group" "main" {
  name       = "student-portal-db-subnets"
  subnet_ids = aws_subnet.private_db[*].id
}

resource "aws_db_instance" "default" {
  identifier              = "student-portal-db"
  engine                  = "mysql"
  instance_class          = var.db_instance_class
  allocated_storage       = var.db_allocated_storage
  storage_encrypted       = true
  publicly_accessible     = false
  multi_az                = var.multi_az
  db_subnet_group_name    = aws_db_subnet_group.main.name
  vpc_security_group_ids  = [aws_security_group.db_sg.id]
  db_name                 = var.db_name
  username                = var.db_username
  password                = var.db_password
  skip_final_snapshot     = true
  backup_retention_period = 7
}
