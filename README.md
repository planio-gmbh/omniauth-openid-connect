# OmniAuth::OpenIDConnect

Authentication strategy using OpenID Connect for OmniAuth. OpenID Connect is a standardized, simple identity layer on top of the OAuth 2.0 protocol.

[![Dependency Status](https://gemnasium.com/badges/github.com/hhorikawa/omniauth-openid-connect.svg)](https://gemnasium.com/github.com/hhorikawa/omniauth-openid-connect)
[![Code Climate](https://codeclimate.com/github/hhorikawa/omniauth-openid-connect/badges/gpa.svg)](https://codeclimate.com/github/hhorikawa/omniauth-openid-connect)
[![Test Coverage](https://codeclimate.com/github/hhorikawa/omniauth-openid-connect/badges/coverage.svg)](https://codeclimate.com/github/hhorikawa/omniauth-openid-connect/coverage)

This package replaces 'omniauth-google-oauth2', 'omniauth-yahoojp', and 'omniauth-azure-oauth2'.


## Tested OpenID Providers

|Organization  |Implementation   |Note            |
|--------------|-----------------|----------------|
|Google        |Google Identity Platform |Developer's Guide https://developers.google.com/identity/protocols/OpenIDConnect  |
|Yahoo! JAPAN  |Yahoo! ID連携 v2          |Developer's Guide https://developer.yahoo.co.jp/yconnect/v2/ |
|Microsoft     |Azure Active Directory   |[Understand the OpenID Connect authentication code flow in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-openid-connect-code)   |
|nov           |OpenID Connect OP sample |https://gitlab.com/horiq/openid_connect_sample

(2017-09) As of now, Azure AD doesn't meet the OpenID Connect specification. You must set `true` of  `:send_client_secret_to_token_endpoint` option.



## What's different

This is derrived work from `jjbohn/omniauth-openid-connect` which appears to be abandoned at this point. I have continued to merge PR's placed against that repo. But I have added enough of my own changes that it is diverged enough to re-release. @ThinkThroughMath actively utilizes this strategy and we will do our best to maintain it.

- Better devise support be returning a default `name` options parameter
- Partial integration of google `nonce` requirement.
- Inclusing of aging PRs from the parent gem this replaces.




## Installation

Clone this repository:

    $ git clone https://github.com/hhorikawa/omniauth-openid-connect.git


Add this line to your application's Gemfile:

    gem 'omniauth-openid-reconnect'

And then execute:

    $ bundle





## Usage

Example configuration
```ruby
config.omniauth :openid_connect, {
  scope: [:openid, :email, :profile, :address],
  response_type: :code,
  client_options: {
    port: 443,
    scheme: "https",
    host: "myprovider.com",
    identifier: ENV["OP_CLIENT_ID"],
    secret: ENV["OP_SECRET_KEY"],
    redirect_uri: "http://myapp.com/users/auth/openid_connect/callback",
  },
}
```

Configuration details:
  * `name` is an optional requirement as of `omniauth-1.2` but it does have an effect with dealing with devise and is the base for which devise uses to create routes identified with `devise_for`. The default is set to the expected camelization of `openid_connect`. If you need to override it you can pass the `name` parameter to the config hash. **Be aware** that what you set this to will be the provider for your devise routes.
  * Although `response_type` is an available option, currently, only `:code`
  is valid. There are plans to bring in implicit flow and hybrid flow at some
  point, but it hasn't come up yet for me. Those flows aren't best practive for
  server side web apps anyway and are designed more for native/mobile apps.
  * If you want to pass `state` paramete by yourself. You can set Proc Object.  
  e.g. `state: Proc.new{ SecureRandom.hex(32) }`
  * `nonce` is optional. If don't want to pass "nonce" parameter to provider, You should specify
  `false` to `send_nonce` option. (default true)
  * Support for other client authentication methods. If don't specified
  `:client_auth_method` option, automatically set `:basic`.
  * Use "OpenID Connect Discovery", You should specify `true` to `discovery` option. (default false)
  * In "OpenID Connect Discovery", generally provider should have Webfinger endpoint.
  If provider does not have Webfinger endpoint, You can specify "Issuer" to option.  
  e.g. `issuer: "https://myprovider.com"`  
  It means to get configuration from "https://myprovider.com/.well-known/openid-configuration".

For the full low down on OpenID Connect, please check out
[the spec](http://openid.net/specs/openid-connect-core-1_0.html).

## Contributing

1. Fork it ( http://github.com/thinkthroughmath/omniauth-openid-reconnect/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
