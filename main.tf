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

resource "ibm_is_ssh_key" "jay-sssh-key" {
  name       = "jay-vsi-1-key"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDUmcGst1I5j165HAHgJ6kEGevbz6ux4RWXj1JjBmU9BU2a6MX9LtwcuSiU5XpflIx2zRD3PyBfTNcQEWgwnff1mah9LmwkwOKTXJDJgZuQWcs6Il/mqlWVzp0ctaRrlAXWbp4nA/UvX8Ty9mx4LjsZ0NdCQp17kcjxruLlUfvX3mbUFldAUoOq0LrZDEY7xtgUNF5tyI5GL9oth2PSbUnXdvFdkRYQjd43BoXiq9V2gXAlPGwdtkmUP1mSXFxwQ8MBbPTMuLIqj3YTzKfFo+sx/3qa+ME6Ob5PXCxiCErvawaZNGqbs6oBPCO2SGR1Ol1Zr+Yct30TGVMYknJtM+RkkM2xKwBZgjU+R8f3Cn1DBhPpBeG6r7wj5nuOhFxJn4wbbDij3fzlqGi9ZZ8yXomtTcmRuM2EBcLfB/x6OIIjgKcusO7L+7g6w6+H+1fL4XXtrVMReAT9tUM7U32N1CI1euPr1ni4TFWpOMVWnEoqJIfd1z+TUgy605x2Y2t9SKE= root@jay-node-000"
}


resource "null_resource" "cat_json_inventory" {
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = "echo hello"
  }
}

