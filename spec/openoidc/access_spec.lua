local utils = require "kong.tools.utils"
local helpers = require "spec.helpers"
local http = require "resty.http"

local oidc_mock_endpoint = "http://oidc-mock:8080"

-- local function get_token(claims, ttl)
--   local req = request.new_from_uri("http://oidc-mock:8080")
--   req.headers:upsert(":method", "POST")

--   if claims or ttl then
--     -- req.headers:append("content-type", "application/x-www-form-urlencoded");
--     local body = nil;

--     if claims then
--       body = "claims=" .. claims;
--     end

--     if ttl then
--       if body then
--         body = body .. "&"
--       end

--       body = body .. "ttl=" .. ttl
--     end
--   end

--   local headers, stream = req:go(600)
--   return stream:get_body_as_string()
-- end

for _, strategy in helpers.each_strategy() do
  describe("openidc plugin", function()
    local proxy_client
    local admin_client
  
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
        hosts = { "oidc-mock.com" },
        service    = service
      }

      local route2 = bp.routes:insert {
        hosts = { "token.com" },
        service    = service
      }

      bp.plugins:insert {
        name     = "openidc",
        route    = { id = route1.id },
        config = {
          ssl_verify = "no",
          -- discovery = "https://pepperitlab.b2clogin.com/pepperitlab.onmicrosoft.com/B2C_1_SignIn/.well-known/openid-configuration"
          discovery = "http://oidc-mock:8080/.well-known/openid-configuration"
        },
      }
  
      assert(helpers.start_kong({
        database   = strategy,
        plugins = "openidc",
      }))
      print("Kong started")
    end)
  
    before_each(function()
      proxy_client = helpers.proxy_client()
      admin_client = helpers.admin_client()
    end)

    after_each(function ()
      proxy_client:close()
      admin_client:close()
    end)

    lazy_teardown(function()
      helpers.stop_kong()
    end)
  
    describe("Checking access_token", function()
      it("should result in access denied because no token was attached to header", function()
        local res = assert(proxy_client:send {
          method = "GET",
          path   = "/healthcheck",
          headers = {
            ["Host"] = "oidc-mock.com"
          }
        })
        local body = assert.res_status(401, res)
      end)

      it("should result in access", function()
        local httpc = http.new()

        local res, err = httpc:request_uri(oidc_mock_endpoint .. "/generate-token", { method = "POST" })
        
        -- local res = assert(proxy_client:send {
        --   method = "POST",
        --   path = "/generate-token",
        --   headers = {
        --     ["Host"] = "token.com"
        --   }
        -- })

        -- print(res)
        -- local token = res.body;

        local res = assert(proxy_client:send {
          method = "GET",
          path   = "/healthcheck",
          headers = {
            ["Host"] = "oidc-mock.com",
            ["Authorization"] = "Bearer " .. res.body
          }
        })
        local body = assert.res_status(200, res)
      end)
    end)
  end)
end