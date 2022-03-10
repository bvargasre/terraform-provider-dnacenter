provider "dnacenter" {
  debug = "true"
}

resource "dnacenter_event_subscription" "example" {
  provider = dnacenter
  parameters {

    description = "string"
    filter {

      event_ids = ["string"]
    }
    name = "string"
    subscription_endpoints {

      instance_id = "string"
      subscription_details {

        connector_type = "string"
        method         = "string"
        name           = "string"
        url            = "string"
      }
    }
    subscription_id = "string"
    version         = "string"
  }
}

output "dnacenter_event_subscription_example" {
  value = dnacenter_event_subscription.example
}