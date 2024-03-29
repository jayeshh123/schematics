# terraform {
#   required_providers {
#     ibm = {
#       source  = "IBM-Cloud/ibm"
#       version = "1.46.0"
#     }
#     http = {
#       source = "hashicorp/http"
#       version = "3.1.0"
#     }
#   }
# }

# variable "api_key"{
#   default = ""
# }

# provider "ibm" {
#   ibmcloud_api_key = var.api_key
#   region           = "us-south"
# }

# variable "pub_key"{
#   default = ""
# }

# resource "ibm_is_ssh_key" "jay-sssh-key" {
#   name       = "jay-vsi-1-key"
#   public_key = var.pub_key
# }

# #===================================================================================
# variable "tf_data_path" {
#   default = "/tmp/.schematics/IBM/tf_data_path"
# }

# // resource to check if the tf_data_path exists or not, if not then create the path.
# resource "null_resource" "check_tf_data_existence" {
#   provisioner "local-exec" {
#     interpreter = ["/bin/bash", "-c"]
#     /* Note: Create the directory only if it does not exist. */
#     command = "if [[ ! -d ${var.tf_data_path} ]]; then mkdir -p ${var.tf_data_path}; fi"
#   }
# }

# // resource to generate ssh key with terraform.
# resource "tls_private_key" "generate_ssh_key" {
#   algorithm  = "RSA"
#   rsa_bits   = 4096
#   depends_on = [null_resource.check_tf_data_existence]
# }

# // resource to write generated ssh-key to a file with 0600 permission
# resource "local_file" "write_ssh_key" {
#   content         = tls_private_key.generate_ssh_key.private_key_pem
#   filename        = format("%s/%s", pathexpand(var.tf_data_path), "id_rsa")
#   file_permission = "0600"
#   depends_on      = [tls_private_key.generate_ssh_key]
# }

# # output "private_key_path" {
# #   value      = format("%s/%s", var.tf_data_path, "id_rsa")
# #   depends_on = [local_file.write_ssh_key]
# # }

# # output "public_key" {
# #   value = tls_private_key.generate_ssh_key.public_key_openssh
# # }

# # output "private_key" {
# #   value = tls_private_key.generate_ssh_key.private_key_pem
# #   sensitive = true
# # }
# ####################################################################################

# variable "ssh_source_cidr_override" {
#   type        = list
#   description = "Override CIDR range that is allowed to ssh to the bastion"
#   default     = ["0.0.0.0/0"]
# }
# variable "bastion_cidr" {
#   description = "Complete CIDR range across all three zones for bastion host subnets"
#   default     = "172.22.192.0/20"
# }
# variable "frontend_cidr" {
#   description = "Complete CIDR range across all three zones for frontend subnets"
#   default     = "172.16.0.0/20"
# }


# #data "external" "env" { program = ["jq", "-n", "env"] }
# locals {
#   region = "us-south"
#   geo    = substr(local.region, 0, 2)
#   schematics_ssh_access_map = {
#     us = ["169.44.0.0/14", "169.60.0.0/14"],
#     eu = ["158.175.0.0/16","158.176.0.0/15","141.125.75.80/28","161.156.139.192/28","149.81.103.128/28"],
#   }
#   schematics_ssh_access = lookup(local.schematics_ssh_access_map, local.geo, ["0.0.0.0/0"])
#   bastion_ingress_cidr  = var.ssh_source_cidr_override[0] != "0.0.0.0/0" ? var.ssh_source_cidr_override : local.schematics_ssh_access
# }

# # locals {
# #   # bastion_cidr_blocks  = [cidrsubnet(var.bastion_cidr, 4, 0), cidrsubnet(var.bastion_cidr, 4, 2), cidrsubnet(var.bastion_cidr, 4, 4)]
# #   frontend_cidr_blocks = [cidrsubnet(var.frontend_cidr, 4, 0), cidrsubnet(var.frontend_cidr, 4, 2), cidrsubnet(var.frontend_cidr, 4, 4)]
# # }

# # Create single zone bastion
# module "bastion" {
#   source                   = "./bastionmodule"
#   ibm_region               = "us-south"
#   bastion_count            = 1
#   unique_id                = "jay-lsf-scale-vpc-1"
#   ibm_is_vpc_id            = "r006-229da5c6-4f1a-44b9-951d-21a8fdb95aa3"
#   ibm_is_resource_group_id = "2cd68a3483634533b41a8993159c27e8"
#   bastion_cidr             = var.bastion_cidr
#   ssh_source_cidr_blocks   = local.bastion_ingress_cidr
#   destination_cidr_blocks  = [var.frontend_cidr]
#   destination_sgs          = [module.frontend.security_group_id]
#   # destination_sg          = [module.frontend.security_group_id, module.backend.security_group_id]
#   # vsi_profile             = "cx2-2x4"
#   # image_name              = "ibm-centos-7-6-minimal-amd64-1"
#   ssh_key_id                = [ibm_is_ssh_key.jay-sssh-key.id]
#   user_data_public          = data.template_file.login_user_data.rendered
#   user_data_private         = data.template_file.login_user_data_private.rendered
#   sg                        = ibm_is_security_group.login_sg.id
# }

# module "frontend" {
#   source                   = "./frontendmodule"
#   ibm_region               = "us-south"
#   unique_id                = "jay-lsf-scale-vpc-1"
#   ibm_is_vpc_id            = "r006-229da5c6-4f1a-44b9-951d-21a8fdb95aa3"
#   ibm_is_resource_group_id = "2cd68a3483634533b41a8993159c27e8"
#   frontend_count           = 1
#   profile                  = "cx2-2x4"
#   ibm_is_image_id          = "r006-7ca7884c-c797-468e-a565-5789102aedc6"
#   ibm_is_ssh_key_id        = [ibm_is_ssh_key.jay-sssh-key.id]
#   subnet_ids               = "0737-8b8cccd9-10a2-475e-945b-7ee62375e384"
#   bastion_remote_sg_id     = module.bastion.security_group_id
#   bastion_subnet_CIDR      = var.bastion_cidr
#   #pub_repo_egress_cidr     = local.pub_repo_egress_cidr
# }

# ####################################################################################
# #===================================================================================
# resource "ibm_is_security_group" "login_sg" {
#   name           = "jay-schematics-login-sg"
#   vpc            = "r006-229da5c6-4f1a-44b9-951d-21a8fdb95aa3"
#   resource_group = "2cd68a3483634533b41a8993159c27e8"
# }

# output "sec_group_id" {
#   value = ibm_is_security_group.login_sg.id
# }

# #===================================================================================
# resource "ibm_is_security_group_rule" "login_ingress_tcp" {
#   #count = length(var.remote_allowed_ips)
#   group     = ibm_is_security_group.login_sg.id
#   direction = "inbound"
#   remote    = "150.239.171.10"
#   tcp {
#     port_min = 22
#     port_max = 22
#   }
# }

# resource "ibm_is_security_group_rule" "login_ingress_tcp_rhsm" {
#   group     = ibm_is_security_group.login_sg.id
#   direction = "inbound"
#   remote    = "161.26.0.0/16"

#   tcp {
#     port_min = 1
#     port_max = 65535
#   }
# }

# resource "ibm_is_security_group_rule" "login_ingress_udp_rhsm" {
#   group     = ibm_is_security_group.login_sg.id
#   direction = "inbound"
#   remote    = "161.26.0.0/16"

#   udp {
#     port_min = 1
#     port_max = 65535
#   }
# }

# #===================================================================================

# data "http" "fetch_myip"{
#   url = "http://ipv4.icanhazip.com"
# }

# resource "ibm_is_security_group_rule" "schematics" {
#   group     = ibm_is_security_group.login_sg.id
#   direction = "inbound"
#   remote    = tolist([chomp(data.http.fetch_myip.response_body)])[0]

#     tcp {
#       port_min = 22
#       port_max = 22
#     }
# }

# output "security_rule_id" {
#   value = ibm_is_security_group_rule.schematics.rule_id
# }

# #===================================================================================
# resource "ibm_is_security_group_rule" "login_egress_tcp" {
#   group     = ibm_is_security_group.login_sg.id
#   direction = "outbound"
#   remote    = ibm_is_security_group.schematics_sg.id
#   tcp {
#     port_min = 22
#     port_max = 22
#   }
# }

# resource "ibm_is_security_group_rule" "login_egress_tcp_rhsm" {
#   group     = ibm_is_security_group.login_sg.id
#   direction = "outbound"
#   remote    = "161.26.0.0/16"
#   tcp {
#     port_min = 1
#     port_max = 65535
#   }
# }

# resource "ibm_is_security_group_rule" "login_egress_udp_rhsm" {
#   group     = ibm_is_security_group.login_sg.id
#   direction = "outbound"
#   remote    = "161.26.0.0/16"
#   udp {
#     port_min = 1
#     port_max = 65535
#   }
# }

# #===================================================================================
# resource "ibm_is_floating_ip" "login_fip" {
#   name           = "jay-schematics-check-fip"
#   target         = ibm_is_instance.login.primary_network_interface[0].id
#   resource_group = "2cd68a3483634533b41a8993159c27e8"
#   lifecycle {
#     ignore_changes = [resource_group]
#   }
# }

# #===================================================================================
# data "template_file" "login_user_data" {
#   template = <<EOF
# #!/usr/bin/env bash
# echo "${tls_private_key.generate_ssh_key.public_key_openssh}" >> ~/.ssh/authorized_keys
# EOF
# }
# data "template_file" "login_user_data_private" {
#   template = <<EOF
# #!/usr/bin/env bash
# echo "${tls_private_key.generate_ssh_key.private_key_pem}" >> ~/.ssh/id_rsa
# EOF
# }
# resource "ibm_is_instance" "login" {
#   name           = "jay-schematics-check"
#   image          = "r006-7ca7884c-c797-468e-a565-5789102aedc6"
#   profile        = "bx2-2x8"
#   zone           = "us-south-3"
#   keys           = [ibm_is_ssh_key.jay-sssh-key.id]
#   user_data      = "${data.template_file.login_user_data.rendered} ${data.template_file.login_user_data_private.rendered}"
#   vpc            = "r006-229da5c6-4f1a-44b9-951d-21a8fdb95aa3"
#   resource_group = "2cd68a3483634533b41a8993159c27e8"

#   # fip will be assinged
#   primary_network_interface {
#     name            = "eth0"
#     subnet          = "0737-8b8cccd9-10a2-475e-945b-7ee62375e384"
#     security_groups = [ibm_is_security_group.login_sg.id, module.frontend.security_group_id]
#   }
# }
# #===================================================================================
# output "floating_ip_address" {
#   value = ibm_is_floating_ip.login_fip.address
# }

# output "primary_network_interface" {
#   value = ibm_is_instance.login.primary_network_interface[0].id
# }

# output "login_id" {
#   value = ibm_is_instance.login.id
# }
# #===================================================================================
# # resource "null_resource" "checking_ssh_key" {
# #   provisioner "local-exec" {
# #     interpreter = ["/bin/bash", "-c"]
# #     command     = "cat /tmp/.schematics/IBM/tf_data_path/id_rsa"
# #   }
# # }
# #===================================================================================
# resource "null_resource" "run_command_on_remote" {
#   connection {
#     type         = "ssh"
#     host         = ibm_is_floating_ip.login_fip.address
#     user         = "root"
#     private_key  = file(format("%s/%s", var.tf_data_path, "id_rsa"))
#     port         = 22
#   }

#   provisioner "file" {
#     source      = "${path.module}/s.sh"
#     destination = "/tmp/script.sh"
#   }

#   provisioner "remote-exec" {
#     inline = [
#       "chmod +x /tmp/script.sh",
#       "/tmp/script.sh",
#     ]     
#   }
#   depends_on = [ibm_is_instance.login, ibm_is_instance.target-node]
# }
# #===================================================================================
# resource "null_resource" "run_ssh_from_local" {
#   provisioner "local-exec" {
#     #interpreter = ["/bin/bash", "-c"]
#     command     = "/bin/bash ${path.module}/script.sh"

#     environment = {
#       "bastion_ip" : module.bastion.floating_ip_address #ibm_is_floating_ip.login_fip.address
#       "target_ip"  : ibm_is_instance.target-node.primary_network_interface.0.primary_ip.0.address
#       "ini_file"   : "${path.module}/inventory.ini"
#       #"key_path"   : format("%s/%s", var.tf_data_path, "id_rsa")
#     }
#   }
#   depends_on = [ibm_is_instance.login, null_resource.run_command_on_remote, ibm_is_instance.target-node]
# }
# #===================================================================================
# resource "ibm_is_security_group" "schematics_sg" {
#   name           = "schematics-target-subnet-sg"
#   vpc            = "r006-229da5c6-4f1a-44b9-951d-21a8fdb95aa3"
#   resource_group = "2cd68a3483634533b41a8993159c27e8"
# }

# output "sg_id" {
#   value = ibm_is_security_group.schematics_sg.id
# }
# #===================================================================================
# resource "ibm_is_security_group_rule" "ingress_tcp" {
#   group     = ibm_is_security_group.schematics_sg.id
#   direction = "inbound"
#   remote    = ibm_is_security_group.login_sg.id

#   tcp {
#     port_min = 22
#     port_max = 22
#   }
# }

# resource "ibm_is_security_group_rule" "ingress_icmp" {
#   group     = ibm_is_security_group.schematics_sg.id
#   direction = "inbound"
#   remote    = "0.0.0.0/0"
#   icmp {
#     code = 0
#     type = 8
#   }
# }
# #===================================================================================
# resource "ibm_is_security_group_rule" "ingress_all_local" {
#   group     = ibm_is_security_group.schematics_sg.id
#   direction = "inbound"
#   remote    = ibm_is_security_group.schematics_sg.id
# }
# #===================================================================================
# resource "ibm_is_security_group_rule" "egress_all" {
#   group     = ibm_is_security_group.schematics_sg.id
#   direction = "outbound"
#   remote    = "0.0.0.0/0"
# }
# #===================================================================================
# data "template_file" "target_node_user_data" {
#   template = <<EOF
# #!/usr/bin/env bash
# echo "${tls_private_key.generate_ssh_key.public_key_openssh}" >> ~/.ssh/authorized_keys
# EOF
# }
# resource "ibm_is_instance" "target-node" {
#   name           = "jay-target-node-schematics"
#   image          = "r006-7ca7884c-c797-468e-a565-5789102aedc6"
#   profile        = "bx2-2x8"
#   zone           = "us-south-3"
#   keys           = [ibm_is_ssh_key.jay-sssh-key.id]
#   user_data      = "${data.template_file.target_node_user_data.rendered} ${file("${path.module}/packages.sh")}"
#   vpc            = "r006-229da5c6-4f1a-44b9-951d-21a8fdb95aa3"
#   resource_group = "2cd68a3483634533b41a8993159c27e8"

#   # fip will be assinged
#   primary_network_interface {
#     name            = "eth0"
#     subnet          = "0737-3695813f-6c12-4afb-b419-4c677189a4e9"
#     security_groups = [ibm_is_security_group.schematics_sg.id, module.bastion.security_group_id]
#   }
# }

# output "private_ip_targetnode" {
#   value = ibm_is_instance.target-node.primary_network_interface[0].primary_ip[0].address
# }
# #===================================================================================
# resource "null_resource" "perform_scale_deployment" {
#   provisioner "local-exec" {
#     interpreter = ["/bin/bash", "-c"]
#     command     = "ansible-playbook -f 32 -i ${path.module}/inventory.ini ${path.module}/playbook.yml"
#   }
#   depends_on = [null_resource.run_ssh_from_local]
#   triggers = {
#     build = timestamp()
#   }
# }
# #===================================================================================