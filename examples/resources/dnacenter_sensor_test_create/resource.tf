
resource "dnacenter_sensor_test_create" "example" {
  provider = dnacenter
  lifecycle {
    create_before_destroy = true
  }
  parameters {
    ap_coverage {

      bands                 = "string"
      number_of_aps_to_test = "string"
      rssi_threshold        = "string"
    }
    connection    = "string"
    model_version = 1
    name          = "string"
    ssids {

      auth_type    = "string"
      categories   = ["string"]
      profile_name = "string"
      psk          = "string"
      qos_policy   = "string"
      ssid         = "string"
      tests {

        config = ["string"]
        name   = "string"
      }
      third_party {

        selected = "false"
      }
    }
  }
}