---
source_file: "server/deploy/integrations/envoy.yaml"
type: "code"
community: "Envoy Config YAML"
location: "L54"
tags:
  - graphify/code
  - graphify/EXTRACTED
  - community/Envoy_Config_YAML
---

# typed_extension_protocol_options

## Connections
- [[clusters]] - `contains` [EXTRACTED]
- [[envoy.extensions.upstreams.http.v3.HttpProtocolOptions]] - `contains` [EXTRACTED]

#graphify/code #graphify/EXTRACTED #community/Envoy_Config_YAML