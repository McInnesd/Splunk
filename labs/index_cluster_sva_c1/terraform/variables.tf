variable "aws_region" {
  default = "ap-southeast-2"
  type = string
}

variable "admin_server_public_ssh_key_name" {
  type = string
}

variable "admin_server_public_ssh_key" {
  type = string
}

variable "jump_server_public_ssh_key_name" {
  type = string
}

variable "jump_server_public_ssh_key" {
  type = string
  default = ""
}