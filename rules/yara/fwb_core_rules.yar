rule FWB_WIFI_PASSWORD_LEAK : credentials high
{
  meta:
    severity = "high"
    category = "credentials"
    description = "Plaintext WiFi or generic password assignment"
  strings:
    $wifi = "wifi_password=" nocase
    $pass = "password=" nocase
  condition:
    any of them
}

rule FWB_MQTT_ENDPOINT : network medium
{
  meta:
    severity = "medium"
    category = "network"
    description = "MQTT broker endpoint found in firmware strings"
  strings:
    $a = "mqtt://"
  condition:
    $a
}

rule FWB_OTA_HTTP_UPDATE : update medium
{
  meta:
    severity = "medium"
    category = "update"
    description = "HTTP OTA update endpoint found"
  strings:
    $a = "ota_update_url=" nocase
    $b = "http://"
  condition:
    $a and $b
}

rule FWB_DEBUG_LEFTOVER : debug low
{
  meta:
    severity = "low"
    category = "debug"
    description = "Debug marker may indicate non-production image"
  strings:
    $a = "DEBUG:"
  condition:
    $a
}
