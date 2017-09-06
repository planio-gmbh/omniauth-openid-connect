# -*- coding:utf-8 -*-

require 'addressable/uri'
require 'timeout'
require 'net/http'
require 'open-uri'
require 'omniauth'
require 'openid_connect'
require 'jwt'

module OmniAuth
  module Strategies

    # Authentication strategy using OpenID Connect
    # Specification::
    #     http://openid.net/specs/openid-connect-core-1_0.html
    class OpenIDConnect
      # TODO: OmniAuth::Strategies::OAuth2 から派生させるようにする.
      #       openid_connect が rack-oauth2, json-jwt に依存している
      #       omniauth-oauth2 は, 他方, oauth2, jwt に依存. その書き換えも必要.
      include OmniAuth::Strategy

      # OpenIDConnect::Client.new() に渡されるオプション.
      option :client_options, {
        # Authentication Request: [REQUIRED] client_id
        identifier: nil,

        # Authentication Request: [REQUIRED] client_secret
        secret: nil,

        # Authentication Request: [REQUIRED]
        redirect_uri: nil,

        # 必須.
        scheme: "https",
        host: nil,
        # scheme の変更だけでいいように, default 値は nil
        port: nil,
        
        authorization_endpoint: "/authorize",
        token_endpoint: "/token",
        userinfo_endpoint: "/userinfo",
        # jwks_uri: '/jwk'   # これはない.
        expires_in: nil
      }
      
      # 指定しなかった場合は, client_options.{scheme, host, port} から
      # discover!().issuer で作られる.
      option :issuer
      
      option :discovery, false
      option :discovery_cache_options, {}
      option :client_signing_alg
      option :client_jwk_signing_key
      option :client_x509_signing_key

      # 必須. こちらが route URL の provider 名になる
      option :name, nil
      
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
      option :response_type, "code"

      # Authentication Request: [RECOMMENDED]
      # 次のいずれか;
      #   1. call()メソッドを持つもの. => new_state() から呼び出される.
      #   2. 文字列
      option :state
      
      # Authentication Request: [NOT RECOMMENDED]
      # 次のいずれか;
      #     'query', 'fragment', 'form_post'
      # 通常は指定不要.
      # See http://qiita.com/TakahikoKawasaki/items/185d34814eb9f7ac7ef3
      # option :response_mode
      
      # true の場合, 認可リクエストに nonce を付ける
      option :send_nonce, true

      # Authentication Request: [OPTIONAL]
      # [:page, :popup, :touch, :wap]
      option :display, nil 
      
      # Authentication Request: [OPTIONAL]
      # [:none, :login, :consent, :select_account]
      option :prompt, nil 

      # Authentication Request: [OPTIONAL]
      option :max_age
      
      # Authentication Request: [OPTIONAL]
      option :ui_locales
      
      # Authentication Request: [OPTIONAL]
      option :id_token_hint
      
      # Authentication Request: [OPTIONAL]
      option :login_hint
      
      # Authentication Request: [OPTIONAL]
      option :acr_values

      option :hd, nil  # what's this?
      option :ux

      # what's this?
      #option :send_scope_to_token_endpoint, true

      # Azure ADは, token_endpoint にも client_id, client_secret を送信しなけ
      # れば失敗する
      option :send_client_secret_to_token_endpoint, false
      
      # token_endpoint へのリクエスト.
      # default 値: :basic
      option :client_auth_method


      attr_accessor :access_token

      uid { user_info.sub }

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
          urls: { website: user_info.website }
        }
      end

      extra do
        {raw_info: user_info.raw_attributes}
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
            scope: access_token.scope
          }
        end
      end


      # @override
      def client
        @client ||= ::OpenIDConnect::Client.new(client_options)
      end


      # このメソッド内で discover! する.
      # 
      # @return [OpenIDConnect::Discovery::Provider::Config::Response] OpenID Provider Configuration Information
      #         <issuer>/.well-known/openid-configuration の内容
      # @exception [OpenIDConnect::Discovery::DiscoveryFailed] 失敗した場合
      #
      # http://openid.net/specs/openid-connect-discovery-1_0.html
      def config
        raise ArgumentError unless (uri = URI.parse(options.issuer)) &&
                                (uri.scheme == 'http' || uri.scheme == 'https')
        
        @config ||= ::OpenIDConnect::Discovery::Provider::Config.discover!(
          options.issuer,
          options.discovery_cache_options&.symbolize_keys
        )
        return @config
      end


      # @override
      def request_phase
        raise ArgumentError if client_options.scheme.blank? || client_options.host.blank?
        if client_options.scheme == "http"
          WebFinger.url_builder = URI::HTTP
          SWD.url_builder = URI::HTTP
        end

        options.issuer = issuer() if options.issuer.blank?
        discover! if options.discovery

        client.redirect_uri = client_options.redirect_uri # See Rack::OAuth2::Client#authorization_uri()
        redirect client.authorization_uri(authorize_params)
      end


      # @override
      # See https://github.com/intridea/omniauth-oauth2/
      def callback_phase
        # 'error' 必須
        # 'error_reason' RFC 6749 にはない。Facebookは 'error' に加えて返す. TODO: 削除してよい?
        error = request.params['error_reason'] || request.params['error']
        if error
          raise CallbackError.new(request.params['error'],
                                  request.params['error_description'] ||
                                               request.params['error_reason'],
                                  request.params['error_uri'])
        end
        if session['omniauth.state']
          # RFC 6749 4.1.2: クライアントからの認可リクエストに stateパラメータ
          # が含まれていた場合は, そのまま返ってくる. [REQUIRED]
          if request.params['state'].to_s.empty? ||
             request.params['state'] != stored_state()
            raise CallbackError.new(:csrf_detected, "'state' parameter error")
          end
        end
                                                                               
        # request.params["code"] のチェック, id_token の取得もこの中で.
        self.access_token = build_access_token()
        #self.access_token = access_token.refresh! if access_token.expired?
        super
      rescue OmniAuth::OpenIDConnect::MissingCodeError => e
        fail!(:missing_code, e)
      rescue CallbackError => e
        fail!(e.error, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

=begin
      def authorization_code
        request.params["code"]
      end
=end

      # @override
      # request_phase() から呼び出される.
      # このメソッド内部で, state値を更新する.
      # @return [Hash] パラメータ.
      def authorize_params
        opts = {
            # OpenIDConnect::Client
            scope: options.scope,
            prompt: options.prompt,
            # Rack::OAuth2::Client
            response_type: options.response_type,

            state: new_state(),
            nonce: (new_nonce if options.send_nonce),
        }
        [:display, :prompt, :max_age, :ui_locales, :id_token_hint, :login_hint,
         :acr_values, :hd, :ux].each do |key|
          opts[key] = options.send(key)
        end

        %w[email realm cid].each do |key|
          opts[key.to_sym] = request.params[key] if request.params[key]
        end

        return opts.reject{|k,v| v.nil?}
      end


      def public_key(kid=nil)
        if options.discovery && kid.present?
          key = config.jwks.select{|k| k["kid"] == kid}.try(:first)
          JSON::JWK.new(key).to_key
        else
          key_or_secret
        end
      end

    private ##############################################

      def issuer
        resource = "#{client_options.scheme}://#{client_options.host}" + ((client_options.port) ? ":#{client_options.port.to_s}" : '')

        # 引数は identifier 一つだけ.
        ::OpenIDConnect::Discovery::Provider.discover!(resource).issuer
      end

      def discover!
        # config() 内で discover! している.
        client_options.authorization_endpoint = config.authorization_endpoint
        client_options.token_endpoint = config.token_endpoint
        client_options.userinfo_endpoint = config.userinfo_endpoint
        client_options.jwks_uri = config.jwks_uri

        client.token_endpoint = config.token_endpoint
        client.userinfo_endpoint = config.userinfo_endpoint
      end

      # @override
      def user_info
        @user_info ||= access_token.userinfo!
      end

      
      # @override
      # callback_phase() から呼び出される.
      # @return [Rack::OAuth2::AccessToken] アクセストークン
      #         'oauth2'パッケージの OAuth2::AccessToken クラスとは別物.
      def build_access_token
        if !request.params["code"]
          raise OmniAuth::OpenIDConnect::MissingCodeError.new(request.params["error"])
        end

        # これはメソッド呼び出し. See Rack::OAuth2::Client
        client.authorization_code = request.params.delete('code')

        # なぜか, callback_phase でも discover! が必要.
        options.issuer = issuer() if options.issuer.blank?
        discover! if options.discovery
        
        # token_endpoint に対して http request を行う.
        # 仕様では grant_type, code, redirect_uri パラメータ
        opts = {
          #scope: (options.scope if options.send_scope_to_token_endpoint),
          client_auth_method: options.client_auth_method,
        }
        if options.send_client_secret_to_token_endpoint
          opts.merge!(
            client_id: client_options.identifier, # Azure AD only.
            client_secret: client_options.secret
          )
        end
        _access_token = client.access_token! opts
        
        header = ::JWT.decoded_segments(_access_token.id_token, false).try(:[],0)
        kid = header["kid"]
        key = public_key(kid)
        _id_token = decode_id_token _access_token.id_token, key

        _id_token.verify!(
              issuer: options.issuer,
              client_id: client_options.identifier,
              nonce: stored_nonce
          )

        return _access_token
      end

      
=begin
      def configure_http_client_ssl
        # http_client は HTTPClient 型
        Rack::OAuth2.http_config do |http_client|
          # OpenSSL::X509::Certificate
          http_client.ssl_config.client_cert = client_options.ssl.certificate
          # OpenSSL::PKey::PKey
          http_client.ssl_config.client_key = client_options.ssl.private_key
        end
      end
      
      def reset_http_client
        Rack::OAuth2.reset_http_config!
      end
=end
         

      def decode_id_token(id_token, key)
        ::OpenIDConnect::ResponseObject::IdToken.decode(id_token, key)
      end

      def client_options
        options.client_options
      end


      def new_state
        state = options.state.call if options.state.respond_to? :call
        session['omniauth.state'] = state || SecureRandom.hex(16)
      end

      
      # 破壊メソッド
      def stored_state
        session.delete('omniauth.state')
      end

      def new_nonce
        session['omniauth.nonce'] = SecureRandom.hex(16)
      end

      # 破壊メソッド
      def stored_nonce
        session.delete('omniauth.nonce')
      end

      # @override
      def session
        @env.nil? ? {} : super
      end

      def key_or_secret
        case options.client_signing_alg
          when :HS256, :HS384, :HS512
            return client_options.secret

          when :RS256, :RS384, :RS512
            if options.client_jwk_signing_key
              return parse_jwk_key(options.client_jwk_signing_key)
            elsif options.client_x509_signing_key
              return parse_x509_key(options.client_x509_signing_key)
            end
          else
            if(client_options.secret)
              return client_options.secret
            end
        end
        return nil
      end

      def parse_x509_key(key)
        OpenSSL::X509::Certificate.new(key).public_key
      end


      # @param [String or Hash] key JSON形式の文字列, またはハッシュ.
      def parse_jwk_key(key)
        if key.is_a?(String)
          json = JSON.parse(key)
        elsif key.is_a?(Hash)
          json = key
        else
          raise TypeError, "key was #{key.class}, #{key.inspect}" 
        end

        if json.has_key?('keys')
          JSON::JWK::Set.new json['keys']
        else
          JSON::JWK.new json
        end
      end

=begin
      def create_rsa_key(mod, exp)
        key = OpenSSL::PKey::RSA.new
        exponent = OpenSSL::BN.new decode(exp)
        modulus = OpenSSL::BN.new decode(mod)
        key.e = exponent
        key.n = modulus
        key
      end
=end
      
      def decode(str)
        UrlSafeBase64.decode64(str).unpack('B*').first.to_i(2).to_s
      end

      # TODO: omniauth-oauth2 を利用する
      class CallbackError < StandardError
        attr_reader :error
        attr_accessor :error_reason, :error_uri

        def initialize(error, error_reason=nil, error_uri=nil)
          @error = error
          self.error_reason = error_reason
          self.error_uri = error_uri
        end

        def message
          [error, error_reason, error_uri].compact.join(' | ')
        end
      end # class CallbackError
      
    end # class OpenIDConnect
  end
end

OmniAuth.config.add_camelization 'openid_connect', 'OpenIDConnect'
