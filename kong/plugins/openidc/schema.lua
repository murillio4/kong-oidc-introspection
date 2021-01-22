return {
    no_consumer = true,
    fields = {
      discovery = { type = "string", required = true, default = "https://.well-known/openid-configuration" },
      timeout = { type = "number", required = false },
      scope = { type = "string", required = false, },
      ssl_verify = { type = "string", required = true, default = "no" }
    }
  }