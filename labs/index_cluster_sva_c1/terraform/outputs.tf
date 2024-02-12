output "jump_server_public_ip" {
  value = module.ec2_splunk_lab["jump"].public_ip
}

output "private_ips" {
  value = { for k, ec2 in module.ec2_splunk_lab : k => ec2.private_ip }
}

output "ec2_username" {
  value = var.ec2_username
}

output "ssh_command" {
  value = "ssh ${var.ec2_username}@${module.ec2_splunk_lab["jump"].public_ip} -i ~/.ssh/id_rsa 'cat .ssh/id_rsa.pub'"
}
