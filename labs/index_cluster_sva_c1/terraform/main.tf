data "aws_availability_zones" "available" {}

locals {
  name   = "splunk-lab-sva-c1"
  region = var.aws_region

  vpc_cidr = "10.0.0.0/21"
  azs      = slice(data.aws_availability_zones.available.names, 0, 1)

  tags = {
    Name       = local.name
    Repository = "https://github.com/mcinnesd/Splunk"
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.5.2"

  name = local.name
  cidr = local.vpc_cidr
  azs  = local.azs

  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 3, k)]
  public_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 5, k + 12)]

  tags = local.tags
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn-ami-hvm-*-x86_64-gp2"]
  }
}

data "aws_ami" "amazon_linux_23" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023*-x86_64"]
  }
}

module "security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 4.0"

  name        = local.name
  description = "Security group for example usage with EC2 instance"
  vpc_id      = module.vpc.vpc_id

  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules       = ["http-80-tcp", "all-icmp", "ssh-tcp"]
  egress_rules        = ["all-all"]

  tags = local.tags
}

locals {
  instance_defaults = {
    create                      = var.jump_server_public_ssh_key != "" ? true : false
    instance_type               = "m5.large"
    availability_zone           = element(module.vpc.azs, 0)
    subnet_id                   = element(module.vpc.private_subnets, 0)
    associate_public_ip_address = false
    user_data = templatefile("${path.module}/templates/default_user_data.tftpl", { user = var.ec2_username, ssh_authorized_key = var.jump_server_public_ssh_key })
  }

  lab_instances = {
    utl-1 = {
      private_ip = "10.0.0.22"
      root_block_device = [
        {
          delete_on_termination = true
          encrypted             = true
          volume_type = "gp3"
          throughput  = 125
          volume_size = 50
        }
      ]
    }
    cm-1 = {
      private_ip = "10.0.0.21"
      root_block_device = [
        {
          delete_on_termination = true
          encrypted             = true
          volume_type = "gp3"
          throughput  = 125
          volume_size = 50
        }
      ]
    }
    idx-1 = {
      private_ip = "10.0.0.11"
      root_block_device = [
        {
          delete_on_termination = true
          encrypted             = true
          volume_type = "gp3"
          throughput  = 125
          volume_size = 50
        }
      ]
    }
    idx-2 = {
      private_ip = "10.0.0.12"
      root_block_device = [
        {
          delete_on_termination = true
          encrypted             = true
          volume_type = "gp3"
          throughput  = 125
          volume_size = 50
        }
      ]
    }
    idx-3 = {
      private_ip = "10.0.0.13"
      root_block_device = [
        {
          delete_on_termination = true
          encrypted             = true
          volume_type = "gp3"
          throughput  = 125
          volume_size = 50
        }
      ]
    }
    sh-1 = {
      private_ip = "10.0.0.31"
      root_block_device = [
        {
          delete_on_termination = true
          encrypted             = true
          volume_type = "gp3"
          throughput  = 125
          volume_size = 50
        }
      ]
    }
    fwd-1 = {
      private_ip = "10.0.0.41"
      root_block_device = [
        {
          delete_on_termination = true
          encrypted             = true
          volume_type = "gp3"
          throughput  = 125
          volume_size = 50
        }
      ]
    }
    fwd-2 = {
      private_ip = "10.0.0.42"
      root_block_device = [
        {
          delete_on_termination = true
          encrypted             = true
          volume_type = "gp3"
          throughput  = 125
          volume_size = 50
        }
      ]
    }
    jump = {
      create                      = true
      private_ip                  = "10.0.3.10"
      associate_public_ip_address = true
      subnet_id                   = element(module.vpc.public_subnets, 0)
      user_data = templatefile("${path.module}/templates/jump_server_user_data.tftpl", { user = var.ec2_username, ssh_authorized_keys = var.admin_computer_public_ssh_keys })
      root_block_device = [
        {
          delete_on_termination = true
          encrypted             = true
          volume_type = "gp3"
          throughput  = 125
          volume_size = 50
        }
      ]
    }
  }
}

module "ec2_splunk_lab" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "5.6.0"

  for_each = local.lab_instances

  name = "${local.name}-${each.key}"

  create = lookup(each.value, "create", local.instance_defaults.create)

  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = lookup(each.value, "instance_type", local.instance_defaults.instance_type)
  availability_zone           = lookup(each.value, "availability_zone", local.instance_defaults.availability_zone)
  subnet_id                   = lookup(each.value, "subnet_id", local.instance_defaults.subnet_id)
  associate_public_ip_address = lookup(each.value, "associate_public_ip_address", local.instance_defaults.associate_public_ip_address)
  private_ip                  = lookup(each.value, "private_ip", null)
  vpc_security_group_ids      = [module.security_group.security_group_id]
  user_data = lookup(each.value, "user_data", local.instance_defaults.user_data)

  enable_volume_tags = false
  root_block_device  = lookup(each.value, "root_block_device", [])

  tags = merge(local.tags, { Name = "${local.name}-${each.key}" })
}
