// A Caddy build with the Corazium module and Caddy's standard modules.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/Agustian16/WAAP-Platform/server/integrations/caddy"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func main() { caddycmd.Main() }
