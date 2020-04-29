
# OmniAuth::OpenIDConnect

Authentication strategy using OpenID Connect for OmniAuth. This package replaces 'omniauth-google-oauth2', 'omniauth-yahoojp', and 'omniauth-azure-oauth2'.

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

    $ git clone https://github.com/netsphere-labs/omniauth-openid-connect.git
    $ rake build
    # rake install:local


Gemfile:

```ruby
    # 認証系
    gem "omniauth"

    # Facebook OAuth2 Strategy for OmniAuth
    # https://github.com/mkdynamic/omniauth-facebook
    gem "omniauth-facebook"

    # OpenID Connect対応
    # googleはこちら。
    gem 'openid_connect', '1.1.5'   # バージョン固定.
    gem "omniauth-openid-connect"
```


And then execute:

    $ bundle

    
### Supported Ruby Versions

OmniAuth::OpenIDConnect is tested under v2.5, v2.6



## Usage

See http://www.nslabs.jp/omniauth-openid-connect.rhtml


### Options Overview

| Field                        | Description                                                                                                                                                   | Required | Default                    | Example/Options                                     |
|------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|----------------------------|-----------------------------------------------------|
| name                         | Arbitrary string to identify connection and identify it from other openid_connect providers                                                                                                                        | no       | String: openid_connect     | :my_idp                                             |
| issuer                       | Root url for the authorization server                                                                                                                         | yes      |                            | https://myprovider.com                              |
| discovery                    | Should OpenID discovery be used. This is recommended if the IDP provides a discovery endpoint. See client config for how to manually enter discovered values. | no       | false                      | one of: true, false                                 |
| client_auth_method           | Which authentication method to use to authenticate your app with the authorization server                                                                     | no       | Sym: basic                 | "basic", "jwks"                                     |
| scope                        | Which OpenID scopes to include (:openid is always required)                                                                                                   | no       | Array<sym> [:openid]       | [:openid, :profile, :email]                         |
| response_type                | Which OAuth2 response type to use with the authorization request. [Security issue] Do not use 'id_token'. 'id_token' is used for only Self-Issued OpenID Providers. Instead, use ['id_token', 'token'] (Implicit Flow).              | no       | String: code               | one of: 'code', ['id_token', 'token']                          |
| state                        | A value to be used for the OAuth2 state parameter on the authorization request. Can be a proc that generates a string.                                        | no       | Random 16 character string | Proc.new { SecureRandom.hex(32) }                   |
| response_mode                | The response mode per [spec](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)                                                              | no       | nil                        | one of: :query, :fragment, :form_post, :web_message |
| display                      | An optional parameter to the authorization request to determine how the authorization and consent page                                                        | no       | nil                        | one of: :page, :popup, :touch, :wap                 |
| prompt                       | An optional parameter to the authrization request to determine what pages the user will be shown                                                              | no       | nil                        | one of: :none, :login, :consent, :select_account    |
| send_scope_to_token_endpoint | Should the scope parameter be sent to the authorization token endpoint?                                                                                       | no       | true                       | one of: true, false                                 |
| post_logout_redirect_uri     | The logout redirect uri to use per the [session management draft](https://openid.net/specs/openid-connect-session-1_0.html)                                   | no       | empty                      | https://myapp.com/logout/callback                   |
| uid_field                    | The field of the user info response to be used as a unique id                                                                                                 | no       | 'sub'                      | "sub", "preferred_username"                         |
| client_options               | A hash of client options detailed in its own section                                                                                                          | yes      |                            |                                                     |


### Additional Configuration Notes

  * `name` is arbitrary, I recommend using the name of your provider. The name
  configuration exists because you could be using multiple OpenID Connect
  providers in a single app.

  **NOTE**: if you use this gem with Devise you should use `:openid_connect` name,
  or Devise would route to 'users/auth/:provider' rather than 'users/auth/openid_connect'

  * `response_type` tells the authorization server which grant type the application wants to use,
  currently, only `'code'` (Authorization Code grant) and `['id_token', 'token']` (Implicit grant) are valid.
  Do not use `id_token`. This is valid only under Self-Issued OpenID Providers.

  * If you want to pass `state` paramete by yourself. You can set Proc Object.
  e.g. `state: Proc.new { SecureRandom.hex(32) }`

  * ON Authorization Code Flow, `nonce` is optional. If you don't want to pass the "nonce" parameter to provider, you should specify
  `false` to `send_nonce` option (default true). On Implicit Flow, the `nonce` is required. `send_nonce` option is ignored.




### Client Config Options

These are the configuration options for the client_options hash of the configuration.

| Field                  | Description                                                     | Default    | Replaced by discovery? |
|------------------------|-----------------------------------------------------------------|------------|------------------------|
| identifier             | The OAuth2 client_id                                            |            |                        |
| secret                 | The OAuth2 client secret                                        |            |                        |
| redirect_uri           | The OAuth2 authorization callback url in your app               |            |                        |
| scheme                 | The http scheme to use                                          | https      |                        |
| host                   | The host of the authorization server                            | nil        |                        |
| port                   | The port for the authorization server                           | 443        |                        |
| authorization_endpoint | The authorize endpoint on the authorization server              | /authorize | yes                    |
| token_endpoint         | The token endpoint on the authorization server                  | /token     | yes                    |
| userinfo_endpoint      | The user info endpoint on the authorization server              | /userinfo  | yes                    |
| jwks_uri               | The jwks_uri on the authorization server                        | /jwk       | yes                    |
| end_session_endpoint   | The url to call to log the user out at the authorization server | nil        | yes                    |





  * Support for other client authentication methods. If don't specified
  `:client_auth_method` option, automatically set `:basic`.
  
  * Use "OpenID Connect Discovery", You should specify `true` to `discovery` option. (default false)
  * In "OpenID Connect Discovery", generally provider should have Webfinger endpoint.
  If provider does not have Webfinger endpoint, You can specify "Issuer" to option.
  e.g. `issuer: "https://myprovider.com"`
  It means to get configuration from "https://myprovider.com/.well-known/openid-configuration".
  * The uid is by default using the `sub` value from the `user_info` response,
  which in some applications is not the expected value. To avoid such limitations, the uid label can be
  configured by providing the omniauth `uid_field` option to a different label (i.e. `preferred_username`)
  that appears in the `user_info` details.
  * The `issuer` property should exactly match the provider's issuer link.
  * The `response_mode` option is optional and specifies how the result of the authorization request is formatted.
  * Some OpenID Connect providers require the `scope` attribute in requests to the token endpoint, even if
  this is not in the protocol specifications. In those cases, the `send_scope_to_token_endpoint`
  property can be used to add the attribute to the token request. Initial value is `true`, which means that the
  scope attribute is included by default.




## Contributing

1. Fork it ( https://github.com/netsphere-labs/omniauth-openid-connect )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Cover your changes with tests and make sure they're green (`bundle install && bundle exec rake test`)
4. Commit your changes (`git commit -am 'Add some feature'`)
5. Push to the branch (`git push origin my-new-feature`)
6. Create new Pull Request
