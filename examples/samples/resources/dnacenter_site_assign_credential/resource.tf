
terraform {
  required_providers {
    dnacenter = {
      version = "0.3.0"
      source  = "hashicorp.com/edu/dnacenter"
      # "hashicorp.com/edu/dnacenter" is the local built source change to "cisco-en-programmability/dnacenter" to use downloaded version from registry
    }
  }
}

provider "dnacenter" {
  debug = "true"
}

resource "dnacenter_site_assign_credential" "example" {
  provider = dnacenter
  lifecycle {
    create_before_destroy = true
  }
  parameters {
    site_id          = "string"
    cli_id           = "string"
    http_read        = "string"
    http_write       = "string"
    snmp_v2_read_id  = "string"
    snmp_v2_write_id = "string"
    snmp_v3_id       = "string"
  }
}