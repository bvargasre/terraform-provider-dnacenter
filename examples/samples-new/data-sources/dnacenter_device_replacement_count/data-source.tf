terraform {
  required_providers {
    dnacenter = {
      version = "0.1.0-alpha"
      source  = "hashicorp.com/edu/dnacenter"
      # "hashicorp.com/edu/dnacenter" is the local built source, change to "cisco-en-programmability/dnacenter" to use downloaded version from registry
    }
  }
}

provider "dnacenter" {
}

data "dnacenter_device_replacement_count" "example" {
  provider = dnacenter
}

output "dnacenter_device_replacement_count_example" {
  value = data.dnacenter_device_replacement_count.example.item
}