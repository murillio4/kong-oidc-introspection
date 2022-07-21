# kong-oidc

Simple kong plugin for openid connect token validation

## Parameters
| Form Parameter | Description | Required | Default |
|---|---|---|---|
|discovery| Openid connect discovery endpoint | true | https://.well-known/openid-configuration | 
| ssl_verify | SSL verificatio | true | no |
| scope | Valid token scope | false |
| audience | Valid audience | false |
| timeout | Request timeout | false |