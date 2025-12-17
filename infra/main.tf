provider "aws" {
  region = "us-east-1"
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# 1. LA BASE DE DONNÉES (Ajouté pour le respect du cahier des charges)
resource "aws_dynamodb_table" "history_table" {
  name           = "SentinelHistory"
  billing_mode   = "PAY_PER_REQUEST" # Gratuit si peu utilisé
  hash_key       = "scan_id"
  attribute {
    name = "scan_id"
    type = "S"
  }
}

# 2. Rôle IAM (Pour que le serveur puisse scanner AWS et écrire en DB)
resource "aws_iam_role" "ec2_role" {
  name = "SentinelEC2Role_Pro"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole", Principal = { Service = "ec2.amazonaws.com" }, Effect = "Allow" }]
  })
}

# On donne les droits d'admin pour être sûr que Prowler puisse tout scanner sans bloquer
resource "aws_iam_role_policy_attachment" "admin_rights" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "SentinelInstanceProfile_Pro"
  role = aws_iam_role.ec2_role.name
}

# 3. Security Group
resource "aws_security_group" "app_sg" {
  name = "sentinel-sg-pro"
  ingress { from_port = 80 to_port = 80 protocol = "tcp" cidr_blocks = ["0.0.0.0/0"] }
  ingress { from_port = 22 to_port = 22 protocol = "tcp" cidr_blocks = ["0.0.0.0/0"] }
  egress { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}

# 4. Bucket S3 Frontend
resource "aws_s3_bucket" "frontend_bucket" {
  bucket = "cloud-sentinel-front-soumia-wiame-amine" # <--- CHANGE ICI
}

# 5. Serveur EC2
resource "aws_instance" "app_server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"
  key_name      = "sentinel-key"
  
  vpc_security_group_ids = [aws_security_group.app_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name # Important pour Prowler !

  user_data = <<-EOF
              #!/bin/bash
              sudo apt-get update
              sudo apt-get install -y docker.io git
              sudo systemctl start docker
              sudo usermod -aG docker ubuntu
              EOF
  tags = { Name = "Sentinel-Server-Pro" }
}

output "server_ip" { value = aws_instance.app_server.public_ip }