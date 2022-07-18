return {
    no_consumer = true,
    fields = {
      discovery = { type = "string", required = true, default = "https://.well-known/openid-configuration" },
      scope = { type = "string", required = false, },
      audience = { type = "string", required = false },
      timeout = { type = "number", required = false },
      ssl_verify = { type = "string", required = true, default = "no" }
    }
  }