package = "kong-plugins-openidc"
version = "dev-1"
source = {
   url = "https://github.com/murillio4/kong-openidc.git"
}
description = {
   homepage = "https://github.com/murillio4/kong-openidc",
   license = "Apache 2.0"
}
dependencies = {
   "lua >= 5.1",
   "lua-resty-openidc ~> 1.6.1-1",
   "lua-resty-http >= 0.15",
   "lua-resty-jwt >= 0.2.2",
   "base64 >= 1.5",
   "penlight >= 1.7.0",
   "json-lua >= 0.1",
}
build = {
   type = "builtin",
   modules = {
      ["kong.plugins.openidc.handler"] = "kong/plugins/openidc/handler.lua",
      ["kong.plugins.openidc.schema"] = "kong/plugins/openidc/schema.lua",
      ["kong.plugins.openidc.access"] = "kong/plugins/openidc/access.lua"
   }
}
