provider "aws" {
  region = "us-east-1" # On travaille en Virginie (c'est le moins cher)
}

# 1. On cherche automatiquement la dernière version d'Ubuntu (Système d'exploitation)
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical (L'éditeur officiel d'Ubuntu)

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# 2. Le Pare-Feu (Security Group)
resource "aws_security_group" "app_sg" {
  name        = "sentinel-security-group"
  description = "Autoriser Web et SSH"

  ingress { # Autoriser tout le monde à voir le site (Port 80)
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress { # Autoriser GitHub à se connecter pour mettre à jour (Port 22)
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress { # Autoriser le serveur à sortir sur Internet (Mises à jour)
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. Le Bucket S3 pour le site Web (Frontend)
resource "aws_s3_bucket" "frontend_bucket" {
  # CHANGE CE NOM ! Il doit être unique au monde sur AWS.
  bucket = "cloud-sentinel-front-soumia-wiame-amine" 
}

# 4. Le Serveur (EC2)
resource "aws_instance" "app_server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"      # Gratuit (Free Tier)
  key_name      = "sentinel-key"  # La clé que tu as créée à l'étape 2
  
  vpc_security_group_ids = [aws_security_group.app_sg.id]

  # Petit script qui s'exécute tout seul au premier allumage pour installer Docker
  user_data = <<-EOF
              #!/bin/bash
              sudo apt-get update
              sudo apt-get install -y docker.io git
              sudo systemctl start docker
              sudo usermod -aG docker ubuntu
              EOF

  tags = {
    Name = "Sentinel-Server"
  }
}

# 5. Afficher l'IP à la fin
output "ip_du_serveur" {
  value = aws_instance.app_server.public_ip
}