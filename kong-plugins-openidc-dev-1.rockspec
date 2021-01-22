package = "kong-plugins-openidc"
version = "dev-1"
source = {
   url = "git+ssh://git@github.com:murillio4/kong-oidc-introspection.git"
}
description = {
   homepage = "https://github.com/murillio4/kong-oidc-introspection",
   license = "Apache 2.0"
}
dependencies = {
   "lua-resty-openidc"
}
build = {
   type = "builtin",
   modules = {
      ["kong.plugins.openidc.handler"] = "kong/plugins/openidc/handler.lua",
      ["kong.plugins.openidc.schema"] = "kong/plugins/openidc/schema.lua"
   }
}
