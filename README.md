# OmniAuth::OpenIDConnect

Authentication strategy using OpenID Connect for OmniAuth. This package replaces 'omniauth-google-oauth2', 'omniauth-yahoojp', and 'omniauth-azure-oauth2'.

[![Dependency Status](https://gemnasium.com/badges/github.com/hhorikawa/omniauth-openid-connect.svg)](https://gemnasium.com/github.com/hhorikawa/omniauth-openid-connect)
[![Code Climate](https://codeclimate.com/github/hhorikawa/omniauth-openid-connect/badges/gpa.svg)](https://codeclimate.com/github/hhorikawa/omniauth-openid-connect)
[![Test Coverage](https://codeclimate.com/github/hhorikawa/omniauth-openid-connect/badges/coverage.svg)](https://codeclimate.com/github/hhorikawa/omniauth-openid-connect/coverage)

The original is [jjbohn/omniauth-openid-connect](https://github.com/jjbohn/omniauth-openid-connect). This repository is a integration of modifications scattered in various places. [Shopify/omniauth-identity](https://github.com/Shopify/omniauth-identity), [patatoid/omniauth-openid-reconnect](https://github.com/patatoid/omniauth-openid-reconnect) and [m0n9oose/omniauth_openid_connect](https://github.com/m0n9oose/omniauth_openid_connect).




## OpenID Connect

If OAuth is simply used for authentication, there is a large security vulnerability. So, each company independently responded.

OpenID Connect is a standardized, simple identity layer on top of the OAuth 2.0 protocol. 
By using OpenID Connect, we don't need to implement variety extensions of each company.

OpenID Connect uses a mechanism `id_token`. In addition to `access_token`, the authentication server and clients exchange 
the `id_token`, and verifying the signature and nonce makes preventing spoofing.

There is no technical continuity with OpenID 2.0 and OpenID Connect. Only names are similar.
For the full low down on OpenID Connect, please check out
[OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html).



## Tested OpenID Providers

|Organization  |Implementation   |Note            |
|--------------|-----------------|----------------|
|Google        |Google Identity Platform |[Developer's Guide](https://developers.google.com/identity/protocols/OpenIDConnect)  |
|Yahoo! JAPAN  |Yahoo! ID連携 v2          |[Developer's Guide](https://developer.yahoo.co.jp/yconnect/v2/) |
|Microsoft     |Azure Active Directory   |[Understand the OpenID Connect authentication code flow in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-openid-connect-code) |
|nov           |OpenID Connect OP sample |[Sample Application](https://gitlab.com/horiq/openid_connect_sample) |
|Red Hat       |Keycloak           |[Securing Applications](https://www.keycloak.org/docs/latest/securing_apps/)|

(2017-09) As of now, Azure AD doesn't meet the OpenID Connect specification. You must set `true` of  `:send_client_secret_to_token_endpoint` option.

## Installation

Clone this repository:

    $ git clone https://github.com/hhorikawa/omniauth-openid-connect.git



And then execute:

    $ bundle





## Usage

See http://www.nslabs.jp/omniauth-openid-connect.rhtml



Configuration details:

  * If you want to pass `state` parameter by yourself. You can set Proc Object.  
  e.g. `state: Proc.new{ SecureRandom.hex(32) }`
  * `send_nonce` is optional. If don't want to pass "nonce" parameter to provider, You should specify
  `false` to `send_nonce` option. (default true)
  * Support for other client authentication methods. If don't specified
  `:client_auth_method` option, automatically set `:basic`.

  * `name` is arbitrary, I recommend using the name of your provider. The name
  configuration exists because you could be using multiple OpenID Connect
  providers in a single app.
  * Although `response_type` is an available option, currently, only `:code`
  is valid. There are plans to bring in implicit flow and hybrid flow at some
  point, but it hasn't come up yet for me. Those flows aren't best practive for
  server side web apps anyway and are designed more for native/mobile apps.




## Contributing

1. Fork it ( https://github.com/hhorikawa/omniauth-openid-connect )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
