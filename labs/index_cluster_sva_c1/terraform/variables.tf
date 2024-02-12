variable "aws_region" {
  default = "ap-southeast-2"
  type    = string
}

variable "ec2_username" {
  default = "ec2-user"
  type    = string
}

variable "admin_computer_public_ssh_keys" {
  type = list(string)
}

variable "jump_server_public_ssh_key" {
  type    = string
  default = ""
}
