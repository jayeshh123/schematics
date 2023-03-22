terraform {
  required_providers {
    ibm = {
      source  = "IBM-Cloud/ibm"
      version = "1.46.0"
    }
    http = {
      source = "hashicorp/http"
      version = "3.1.0"
    }
  }
}

variable "api_key"{
  default = ""
}

provider "ibm" {
  ibmcloud_api_key = var.api_key
  region           = "us-south"
}

variable "pub_key"{
  default = ""
}

resource "ibm_is_ssh_key" "jay-sssh-key" {
  name       = "jay-vsi-1-key"
  public_key = var.pub_key
}

#===================================================================================
resource "ibm_is_security_group" "login_sg" {
  name           = "jay-schematics-check-sg"
  vpc            = "r006-229da5c6-4f1a-44b9-951d-21a8fdb95aa3"
  resource_group = "2cd68a3483634533b41a8993159c27e8"
}

output "sec_group_id" {
  value = ibm_is_security_group.login_sg.id
}

#===================================================================================
resource "ibm_is_security_group_rule" "login_ingress_tcp" {
  #count = length(var.remote_allowed_ips)
  group     = ibm_is_security_group.login_sg.id
  direction = "inbound"
  remote    = "150.239.171.10"
  tcp {
    port_min = 22
    port_max = 22
  }
}

resource "ibm_is_security_group_rule" "login_ingress_tcp_rhsm" {
  group     = ibm_is_security_group.login_sg.id
  direction = "inbound"
  remote    = "161.26.0.0/16"

  tcp {
    port_min = 1
    port_max = 65535
  }
}

resource "ibm_is_security_group_rule" "login_ingress_udp_rhsm" {
  group     = ibm_is_security_group.login_sg.id
  direction = "inbound"
  remote    = "161.26.0.0/16"

  udp {
    port_min = 1
    port_max = 65535
  }
}

#===================================================================================

data "http" "fetch_myip"{
  url = "http://ipv4.icanhazip.com"
}

resource "ibm_is_security_group_rule" "schematics" {
  group     = ibm_is_security_group.login_sg.id
  direction = "inbound"
  remote    = tolist([chomp(data.http.fetch_myip.response_body)])[0]

    tcp {
      port_min = 22
      port_max = 22
    }
}

output "security_rule_id" {
  value = ibm_is_security_group_rule.schematics.rule_id
}

#===================================================================================
# resource "ibm_is_security_group_rule" "login_egress_tcp" {
#   group     = ibm_is_security_group.login_sg.id
#   direction = "outbound"
#   remote    = var.remote
#   tcp {
#     port_min = 22
#     port_max = 22
#   }
# }

resource "ibm_is_security_group_rule" "login_egress_tcp_rhsm" {
  group     = ibm_is_security_group.login_sg.id
  direction = "outbound"
  remote    = "161.26.0.0/16"
  tcp {
    port_min = 1
    port_max = 65535
  }
}

resource "ibm_is_security_group_rule" "login_egress_udp_rhsm" {
  group     = ibm_is_security_group.login_sg.id
  direction = "outbound"
  remote    = "161.26.0.0/16"
  udp {
    port_min = 1
    port_max = 65535
  }
}

#===================================================================================
resource "ibm_is_floating_ip" "login_fip" {
  name           = "jay-schematics-check-fip"
  target         = ibm_is_instance.login.primary_network_interface[0].id
  resource_group = "2cd68a3483634533b41a8993159c27e8"
  lifecycle {
    ignore_changes = [resource_group]
  }
}

#===================================================================================
resource "ibm_is_instance" "login" {
  name           = "jay-schematics-check"
  image          = "r006-7ca7884c-c797-468e-a565-5789102aedc6"
  profile        = "bx2-2x8"
  zone           = "us-south-3"
  keys           = [ibm_is_ssh_key.jay-sssh-key.id]
  #user_data      = var.user_data
  vpc            = "r006-229da5c6-4f1a-44b9-951d-21a8fdb95aa3"
  resource_group = "2cd68a3483634533b41a8993159c27e8"

  # fip will be assinged
  primary_network_interface {
    name            = "eth0"
    subnet          = "0737-8b8cccd9-10a2-475e-945b-7ee62375e384"
    security_groups = [ibm_is_security_group.login_sg.id]
  }
}

#===================================================================================
output "floating_ip_address" {
  value = ibm_is_floating_ip.login_fip.address
}

output "primary_network_interface" {
  value = ibm_is_instance.login.primary_network_interface[0].id
}

output "login_id" {
  value = ibm_is_instance.login.id
}
#===================================================================================
resource "null_resource" "cat_json_inventory" {
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = "echo hello"
  }
}
#===================================================================================
