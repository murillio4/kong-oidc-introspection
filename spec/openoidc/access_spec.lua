local utils = require "kong.tools.utils"
local helpers = require "spec.helpers"


local httpc = require("resty.http").new()
local oidc_mock_endpoint = "http://oidc-mock:8080"

local function get_token(options)
  options = options or {}
  local body = {}

  if options.claims then
    table.insert(body, "claims=" .. options.claims)
  end
  if options.ttl then 
    table.insert(body, "ttl=" .. options.ttl)
  end
  if options.aud then
    table.insert(body, "aud=" .. options.aud)
  end

  local res, err = httpc:request_uri(oidc_mock_endpoint .. "/generate-token", { 
    method = "POST",
    headers = {
      ["Content-Type"] = "application/x-www-form-urlencoded",
    },
    body = table.concat(body, "&")
 })

 if err then
  return nil, err
 end

 return res.body
end

for _, strategy in helpers.all_strategies() do
  describe("Plugin: oidc auth [#" .. strategy .. "]", function()
    local proxy_client
  
    lazy_setup(function()
      local bp = helpers.get_db_utils(strategy, {
        "routes",
        "services",
        "plugins",
      }, { "openidc" })

      local service = bp.services:insert({
        protocol = "http",
        host     = "oidc-mock",
        port     = 8080,
      })

      local route1 = bp.routes:insert {
        hosts = { "auth1.com" },
        service    = service
      }

      local route2 = bp.routes:insert {
        hosts = { "auth2.com" },
        service    = service
      }

      bp.plugins:insert {
        name     = "openidc",
        route    = { id = route1.id },
        config = {
          ssl_verify = "no",
          discovery = "http://oidc-mock:8080/.well-known/openid-configuration"
        },
      }

      bp.plugins:insert {
        name     = "openidc",
        route    = { id = route2.id },
        config = {
          ssl_verify = "no",
          discovery = "http://oidc-mock:8080/.well-known/openid-configuration",
          audience = "test"
        },
      }
  
      assert(helpers.start_kong({
        database = strategy,
        plugins = "openidc",
      }))

      proxy_client = helpers.proxy_client()
    end)

    lazy_teardown(function()
      if proxy_client then
        proxy_client:close()
      end

      helpers.stop_kong()
    end)
  
    describe("Checking access_token", function()
      it("should result in access denied because no token was attached to header", function()
        local res = assert(proxy_client:send {
          method = "GET",
          path   = "/healthcheck",
          headers = {
            ["Host"] = "auth1.com"
          }
        })
        local body = assert.res_status(401, res)
      end)

      it("should result in access", function()
        local token, err = get_token()
        local res = assert(proxy_client:send {
          method = "GET",
          path   = "/healthcheck",
          headers = {
            ["Host"] = "auth1.com",
            ["Authorization"] = "Bearer " .. token
          }
        })
        local body = assert.res_status(200, res)
      end)
    end)

    describe("Checking access_token with aud", function()
      it("should result in access denied because no audience", function()
        local token, err = get_token()
        local res = assert(proxy_client:send {
          method = "GET",
          path   = "/healthcheck",
          headers = {
            ["Host"] = "auth2.com",
            ["Authorization"] = "Bearer " .. token
          }
        })
        local body = assert.res_status(403, res)
      end)

      it("should result in access denied because wrong audience", function()
        local token, err = get_token({
          aud = "asd"
        })

        local res = assert(proxy_client:send {
          method = "GET",
          path   = "/healthcheck",
          headers = {
            ["Host"] = "auth2.com",
            ["Authorization"] = "Bearer " .. token
          }
        })
        local body = assert.res_status(403, res)
      end)

      it("should result in access", function()
        local token, err = get_token({
          aud = "test"
        })
        local res = assert(proxy_client:send {
          method = "GET",
          path   = "/healthcheck",
          headers = {
            ["Host"] = "auth2.com",
            ["Authorization"] = "Bearer " .. token
          }
        })
        local body = assert.res_status(200, res)
      end)
    end)
  end)
end