# -*- coding:utf-8 -*-
# frozen_string_literal: true

#require 'addressable/uri'
require 'timeout'
require 'net/http'
require 'omniauth'
require 'openid_connect'
#require 'jwt'
require 'forwardable'


module OmniAuth
  module Strategies

    # Authentication strategy using OpenID Connect
    # Specification::
    #     http://openid.net/specs/openid-connect-core-1_0.html
    class OpenIDConnect
      # OmniAuth::Strategies::OAuth2 から派生させるのは大変.
      # - openid_connect が rack-oauth2, json-jwt に依存している
      # - 他方, omniauth-oauth2 は, oauth2, jwt に依存. その書き換えも必要.
      include OmniAuth::Strategy

      extend Forwardable

      def_delegator :request, :params
      
      # [REQUIRED] こちらが route URL の provider 名になる
      option :name, 'openid_connect'

      # instead of hard coding client_options in your omniauth initializer, you
      # may pass a class that determines these values at runtime to support
      # multiple tenants / different openid connect providers.
      #
      # The tenant provider is initialized with this strategy and must provide
      # client_options, issuer and scope methods returning the respective
      # configuration values.
      #
      # Further, it must provide an info method that implements any mapping
      # necessary to turn the raw_attributes data from the oidc provider into
      # an application specific hash of user attributes (i.e., for creating
      # user accounts on the fly).
      option :tenant_provider, nil

      # set a global redirect_uri when using a tenant_provider
      option :redirect_uri, nil

      # OpenIDConnect::Client.new() に渡されるオプション.
      option(:client_options,
                # Authentication Request: [REQUIRED] client_id
                # Rack::OAuth2::Client
                identifier: nil,

                # Authentication Request: [REQUIRED] client_secret
                # On Implicit Flow, MUST NOT set this option.
                # Rack::OAuth2::Client
                secret: nil,

                # Authentication Request: [REQUIRED]
                # Rack::OAuth2::Client
                redirect_uri: nil,

                # [REQUIRED] authorization_endpoint のホスト.
                # Rack::OAuth2::Client
                scheme: 'https',
                host: nil,
                port: nil,

                # discovery: falseの時に指定.
                # Rack::OAuth2::Client
                authorization_endpoint: '/authorize', # client_options に渡す

                # Rack::OAuth2::Client
                token_endpoint: '/token', # client_options に渡す

                # OpenIDConnect::Client
                userinfo_endpoint: '/userinfo', # client_options に渡す

                # OpenIDConnect::Client
                expires_in: nil,   # client_options に渡す
            )

      option :jwks_uri, '/jwk'
      option :end_session_endpoint, nil

      # 指定しなかった場合は, client_options.{scheme, host, port} から作られる.
      option :issuer

      option :discovery, false

      # Required if you don't use 'discovery'.
      # IdP's public keys. NOT client's.
      option :client_jwk_signing_key
      option :client_x509_signing_key

      ##############################
      # Authentication Request
      
      # Authentication Request: [REQUIRED]
      # 'openid' は必須.
      # 加えて, OpenID Connect で定義: 'profile', 'email', 'address', 'phone',
      #         および, 認可サーバで定義されたもの.
      option :scope, [:openid]

      # Authentication Request: [REQUIRED]
      # OpenID Connect は、拡張された複数 response_type を使う.
      # See https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
      # ただし, Webアプリでは 'code' 決め打ちでよい.
      # See http://oauth.jp/blog/2015/01/06/oauth2-multiple-response-type/
      option :response_type, 'code'     # one of 'code', ['id_token', 'token']

      # Authentication Request: [RECOMMENDED]
      # call()メソッドを持つこと. => new_state() から呼び出される.
      option :state

      # Authentication Request: [NOT RECOMMENDED]
      # 通常は指定不要.
      # See http://qiita.com/TakahikoKawasaki/items/185d34814eb9f7ac7ef3
      # 'web_message' is for SPAs.
      option :response_mode  # one of 'query', 'fragment', 'form_post', 'web_message'

      # Authentication Request: [OPTIONAL]
      # value is one of [:page, :popup, :touch, :wap]
      option :display, nil

      # Authentication Request: [OPTIONAL]
      # value is one of [:none, :login, :consent, :select_account]
      option :prompt, nil

      # Restrict user domain name.
      # See https://developers.google.com/identity/protocols/OpenIDConnect#hd-param
      option :hd, nil
      
      # Authentication Request: [OPTIONAL]
      option :max_age

      # not option, but by request.params 
      #option :ui_locales
      #option :id_token_hint
      #option :login_hint

      # Authentication Request: [OPTIONAL]
      option :acr_values

      # Authentication Request: true の場合, nonce を付ける
      # On Implicit Flow, the `nonce` is required. `send_nonce` option is
      # ignored.
      option :send_nonce, true

      # Must verify the id_token. So remove this option.
      #option :verify_id_token, nil

      option :ux

      option :extra_authorize_params, {}

      ##############################
      # token_endpoint

      # token_endpoint: 仕様に準拠しない IdP 対策か。どの製品?
      # 仕様では grant_type, code, redirect_uri パラメータのみ.
      option :send_scope_to_token_endpoint, false

      # token_endpoint へのリクエスト.
      # One of...
      #   :basic           "client_secret_basic": The client uses HTTP Basic.
      #   :jwt_bearer
      #   :saml2_bearer
      #   :mtls
      #   :secret_in_body  "client_secret_post": The client uses the HTTP POST
      #                    parameters.
      #   n/a              "none": The client is a public client as defined in
      #                    OAuth 2.0, Section 2.1, and does not have a client
      #                    secret.
      # default value is :basic
      # See Rack::OAuth2::Client
      # RFC 8414 `token_endpoint_auth_methods_supported` のなかから選ぶ.
      option :client_auth_method

      option :post_logout_redirect_uri

      # Any field from user_info to be processed as UID
      option :uid_field, 'sub'

      ##############################

      # [Rack::OAuth2::AccessToken] アクセストークン
      attr_reader :access_token

      # @override
      def uid
        user_info.raw_attributes[options.uid_field.to_sym] || user_info.sub
      end

      info do
        {
          name: user_info.name,
          email: user_info.email,
          nickname: user_info.preferred_username,
          first_name: user_info.given_name,
          last_name: user_info.family_name,
          gender: user_info.gender,
          image: user_info.picture,
          phone: user_info.phone_number,
          urls: { website: user_info.website },
        }
      end

      extra do
        raw_info = fix_user_info(user_info).raw_attributes
        {
          raw_info: raw_info,
          tenant_info: tenant&.info(raw_info)
        }
      end

      credentials do
        if !access_token
          {}
        else
          {
            id_token: access_token.id_token,
            token: access_token.access_token,
            refresh_token: access_token.refresh_token,
            expires_in: access_token.expires_in,
            scope: access_token.scope,
          }
        end
      end

      def tenant
        @tenant ||= options.tenant_provider&.new(self)
      end

      def initialize(app, *args, &block)
        if args.last.is_a?(Hash)
          OmniAuth::OpenIDConnect.hash_deep_check(self.class.default_options,
                                                  args.last)
        end
        super
      end


      # client_options から OpenIDConnect::Client インスタンスを構築.
      # @return [OpenIDConnect::Client] サーバとのconnection
      def client
        @client ||= ::OpenIDConnect::Client.new(client_options)
      end


      # OpenID Provider Configuration Information を得る.
      # このメソッド内で Config.discover! する.
      #
      # @return [OpenIDConnect::Discovery::Provider::Config::Response] OpenID Provider Configuration Information
      #         <issuer>/.well-known/openid-configuration の内容
      # @raise [OpenIDConnect::Discovery::DiscoveryFailed] 失敗した場合
      #
      # http://openid.net/specs/openid-connect-discovery-1_0.html
      def config
        OmniAuth::OpenIDConnect::Configuration.instance.config(issuer)
      end


      # @override
      # request_phase() と callback_phase() の開始前に呼び出される.
      def setup_phase
        if tenant
          options.issuer = tenant.issuer
          if scope = tenant.scope
            options.scope = scope
          end

          options.client_options = tenant.client_options
          if uri = options.redirect_uri
            options.client_options[:redirect_uri] ||= options.redirect_uri
          end
        end

        super

        @issuer = if options.issuer
                    options.issuer
                  else
                    client_options.scheme + '://' + client_options.host +
                      (client_options.port ? client_options.port.to_s : '')
                  end
        unless (uri = URI.parse(@issuer)) &&
               ['http', 'https'].include?(uri.scheme)
          raise ArgumentError, "Invalid issuer URI scheme"
        end

        # これは discover!の前に設定.
        if client_options.scheme == "http"
          WebFinger.url_builder = URI::HTTP
          SWD.url_builder = URI::HTTP
        end
        discover! if options.discovery

        if configured_response_type != 'code' &&
           configured_response_type != 'id_token token'
          raise ArgumentError, "Invalid response_type"
        end
        if configured_response_type == 'id_token token'
          if client_options.secret
            raise ArgumentError, "MUST NOT set client_secret on Implicit Flow"
          end
        end
      end


      # @override
      def request_phase
        # client() 内で client_options から OpenIDConnect::Client を構築.
        redirect client().authorization_uri(authorize_params)
      end


      # @override
      # See https://github.com/intridea/omniauth-oauth2/
      def callback_phase
        # 'error' [REQUIRED]  Ref. RFC 6749
        #     invalid_request
        #     unauthorized_client
        #     etc.
        if params['error']
          error_description = params['error_description'] || params['error_reason']
          raise CallbackError.new(params['error'],
                                  error_description,   # optional
                                  params['error_uri']) # optional
        end
        if session['omniauth.state'] &&
           (params['state'].to_s.empty? ||
            params['state'] != session.delete('omniauth.state'))
          # RFC 6749 4.1.2: クライアントからの認可リクエストに stateパラメータ
          # が含まれていた場合は, そのまま返ってくる. [REQUIRED]
          raise CallbackError.new(:csrf_detected, "Invalid 'state' parameter")
        end

        case configured_response_type
        when 'code'
          # params["code"] のチェック, id_token の取得もこの中で.
          # @access_token の設定もこの中で.
          authorization_code_flow_callback_phase()
        when 'id_token token'
          implicit_flow_callback_phase()
        end

        super
      rescue CallbackError, OmniAuth::OpenIDConnect::Error => e
        fail!(e.error, e)
      rescue ::Rack::OAuth2::Client::Error => e
        fail!(e.response[:error], e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
#      rescue StandardError => e
#        fail!(:token_verification_failed, e)
      end


      def other_phase
        if logout_path_pattern.match?(current_path)
          #options.issuer = issuer if options.issuer.to_s.empty?
          #discover!
          setup_phase()  # issuer の設定と discover!
          return redirect(end_session_uri) if end_session_uri
        end
        call_app!
      end

      #def authorization_code  ... params.delete() しないといかん. Remove.
      #  params['code']
      #end

      def end_session_uri
        return unless end_session_endpoint_is_valid?

        end_session_uri = URI(client_options.end_session_endpoint)
        end_session_uri.query = encoded_post_logout_redirect_uri
        end_session_uri.to_s
      end


      # request_phase() から呼び出される.
      # このメソッド内部で, state値を更新する.
      # @return [Hash] パラメータ.
      def authorize_params
        opts = {
          # OpenIDConnect::Client
          scope: options.scope,
          prompt: options.prompt,
          # Rack::OAuth2::Client#authorization_uri()
          response_type: configured_response_type,
          # Others
          state: new_state(),
          response_mode: options.response_mode,
          nonce: (new_nonce if options.send_nonce || configured_response_type == 'id_token token'),
          hd: options.hd,
        }

        unless options.extra_authorize_params.empty?
          opts.merge!(options.extra_authorize_params)
        end

        # Optional params.
        %i[display max_age acr_values ux].each do |key|
          opts[key] = options.send(key)
        end

        # end-user's preferred params.
        ['ui_locales', 'id_token_hint', 'login_hint', 'claims_locales', # OpenID Connect Core 1.0
         # extensions
         'email', 'realm', 'cid', 'chem'].each do |key|
          opts[key.to_sym] = params[key] if params[key]
        end

        return opts.reject { |_k, v| v.nil? }
      end


      # @return [JSON::JWK::Set or JSON::JWK] IdP's RSA public keys. NOT client's.
      def public_key(kid = nil)
        # [Security issue] Do not call key_or_secret() here.
        
        if options.discovery
          # ここで jwks_uri へのアクセスが発生.
          config().jwks # setのままでOK
        else
          if options.client_jwk_signing_key
            return OmniAuth::OpenIDConnect.parse_jwk_key(
                     options.client_jwk_signing_key, kid)
          elsif options.client_x509_signing_key
            return OmniAuth::OpenIDConnect.parse_x509_key(
                     options.client_x509_signing_key, kid)
          end
          raise ArgumentError, "internal error: missing RSA public key"
        end
      end


    private ##############################################

      # @return [String] options.issuer または client_options からつくった
      #                  issuer.
      # 設定は setup_phase() 内で行う.
      attr_reader :issuer

      def discover!
        raise "internal bug" if !options.discovery
        
        # config() 内で, issuer を引数にして, 実際に discover! している.
        client_options.authorization_endpoint = config().authorization_endpoint
        client_options.token_endpoint = config().token_endpoint
        client_options.userinfo_endpoint = config().userinfo_endpoint
        # OpenIDConnect::Discovery::Provider::Config::Response に expires_in は
        # ない.
        #client_options.expires_in = config().expires_in

        # client_options に jwks_uri, end_session_endpoint はない.
        options.jwks_uri = config().jwks_uri
        if config().respond_to?(:end_session_endpoint)
          options.end_session_endpoint = config().end_session_endpoint
        end

        if config().respond_to?(:token_endpoint_auth_methods_supported)
          if config().token_endpoint_auth_methods_supported.include?('client_secret_basic')
            options.client_auth_method = :basic
          elsif config().token_endpoint_auth_methods_supported.include?('client_secret_post')
            options.client_auth_method = :secret_in_body
          end
        end
      end


      # @override
      def user_info
        @user_info ||= access_token.userinfo!
      end

      # Google sends the string "true" as the value for the field 
      # 'email_verified' while a boolean is expected.
      def fix_user_info(user_info)
        raise TypeError if !user_info
        
        if user_info.email_verified.is_a? String
          user_info.email_verified = 
                            (user_info.email_verified.casecmp("true") == 0)
        end
        #user_info.gender = nil # in case someone picks something else than male or female, we don't need it anyway
        user_info
      end
      

      # callback_phase() から呼び出される.
      # @return [Rack::OAuth2::AccessToken] アクセストークン
      #         'oauth2'パッケージの OAuth2::AccessToken クラスとは別物.
      # @raise [OmniAuth::OpenIDConnect::MissingCodeError] code がない.
      def authorization_code_flow_callback_phase
        unless params["code"]
          raise OmniAuth::OpenIDConnect::MissingCodeError, "Missing 'code' param"
        end

        # これはメソッド呼び出し. See Rack::OAuth2::Client
        client.authorization_code = params.delete('code')

        # token_endpoint に対して http request を行う.
        # 仕様では grant_type, code, redirect_uri パラメータ
        opts = {
          scope: (options.scope if options.send_scope_to_token_endpoint),
          client_auth_method: options.client_auth_method
        }
        @access_token = client.access_token! opts
        raise TypeError, "internal error" if !@access_token.is_a?(Rack::OAuth2::AccessToken)

        # 鍵を選ぶ。"{ヘッダ部}.{ペイロード部}.{シグネチャ部}" と、ピリオドで
        # 区切られている。ヘッダ部にアルゴリズムが書かれている.
        header = (JSON::JWS.decode_compact_serialized @access_token.id_token, :skip_verification).header
        #header = ::JWT.decoded_segments(actoken.id_token, false)[0]
        key = key_or_secret header

        # このなかで署名の検証も行う. => JSON::JWS::VerificationFailed
        id_token = ::OpenIDConnect::ResponseObject::IdToken.decode(
                                              @access_token.id_token, key)
        verify_id_token!(id_token)

        @access_token
      end


      # [Security issue] On Authorization Code Flow, use key_or_secret, not
      # public_key. On the other hand, you have to use public_key on Implicit
      # Flow.
      #def decode_id_token(id_token)
           
      def client_options
        options.client_options
      end


      def new_state
        state = if options.state.respond_to?(:call)
                  if options.state.arity == 1
                    options.state.call(env)
                  else
                    options.state.call
                  end
                end
        session['omniauth.state'] = state || SecureRandom.hex(16)
      end


      def new_nonce
        session['omniauth.nonce'] = SecureRandom.hex(16)
      end


      # @override
      def session
        if OmniAuth.config.test_mode
          @env ||= {}
          @env["rack.session"] ||= {}
        end
        super # just, return @env['rack.session']
      end


      # HMAC-SHA256 の場合は, client_secret を共通鍵とする
      # RSAの場合は, 認証サーバの公開鍵を使う
      def key_or_secret header
        raise TypeError if !header
        
        case header['alg'].to_sym
        when :HS256, :HS384, :HS512
          client_options.secret
        when :RS256, :RS384, :RS512
          # public_key() のなかで, :client_jwk_signing_key と
          # :client_x509_signing_key を参照する
          public_key(header['kid'])
        else
          # ES256 : ECDSA using P-256 curve and SHA-256 hash
          raise ArgumentError, "unsupported alg: #{header['alg']}"
        end
      end

      # [Security issue] Do not use params['redirect_uri']
      #def redirect_uri

      
      def encoded_post_logout_redirect_uri
        return unless options.post_logout_redirect_uri

        URI.encode_www_form(
          post_logout_redirect_uri: options.post_logout_redirect_uri
        )
      end

      def end_session_endpoint_is_valid?
        client_options.end_session_endpoint &&
          client_options.end_session_endpoint =~ URI::DEFAULT_PARSER.make_regexp
      end

      def logout_path_pattern
        @logout_path_pattern ||= %r{\A#{Regexp.quote(request_path)}(/logout)}
      end


      # Implicit Flow:
      # id_token と同時に access token を得る. id_token または access token の
      # いずれかが改竄されている risk がある。(Token Hijacking)
      # そのため,
      # (1) IdP の公開鍵によって, id_token の署名を検証しなければならない.
      #     header で鍵を選ぶのではなく, 公開鍵決め打ちにしなければならない.
      # (2) access token を id_token によって検証しなければならない.
      def implicit_flow_callback_phase
        if !params['access_token'] || !params['id_token']
          raise OmniAuth::OpenIDConnect::MissingIdTokenError, "Missing 'access_token' or 'id_token' param"
        end

        # このなかで署名の検証も行う. => JSON::JWS::VerificationFailed
        id_token = ::OpenIDConnect::ResponseObject::IdToken.decode(
                       params['id_token'],
                       public_key())
        # 内容の検証
        verify_id_token!(id_token)

        # さらに, access token を検証しなければならない.
        OmniAuth::OpenIDConnect.verify_access_token(
                         params['access_token'], id_token, params['id_token'])

        user_data = decode_id_token(params['id_token']).raw_attributes
        env['omniauth.auth'] = AuthHash.new(
          provider: name,
          uid: user_data['sub'],
          info: { name: user_data['name'], email: user_data['email'] },
          extra: { raw_info: user_data }
        )
      end


      def configured_response_type
        @configured_response_type ||= if options.response_type.is_a?(Array)
                                        options.response_type.sort.join(' ')
                                      else
                                        options.response_type.to_s
                                      end
      end


      def verify_id_token!(decoded_id_token)
        raise TypeError if !decoded_id_token.is_a?(::OpenIDConnect::ResponseObject::IdToken)
        decoded_id_token.verify!(issuer: issuer,
                                 client_id: client_options.identifier,
                                 nonce: session.delete('omniauth.nonce') )
      end


      class CallbackError < StandardError
        attr_reader :error
        attr_reader :error_reason, :error_uri

        # @param error [REQUIRED] a single ASCII error code. Ref. RFC 6749
        # @param error_reason [OPTIONAL] Human-readable text.
        # @param error_uri [OPTIONAL]
        def initialize(error, error_reason = nil, error_uri = nil)
          raise TypeError if !error
          
          @error = error
          @error_reason = error_reason
          @error_uri = error_uri

          super [error, error_reason, error_uri].compact.join(' | ')
        end
      end # class CallbackError

    end # class OpenIDConnect
  end # module Strategies
end # module OmniAuth

OmniAuth.config.add_camelization 'openid_connect', 'OpenIDConnect'
