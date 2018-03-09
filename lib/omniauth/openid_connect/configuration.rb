require 'singleton'

module OmniAuth
  module OpenIDConnect
    class Configuration
      inlcude Singleton

      def initialize
        @idp_config = {}
      end

      def config(issuer)
        @idp_config[issuer] ||=
          ::OpenIDConnect::Discovery::Provider::Config.discover!(issuer)
        @idp_config[issuer]
      end
    end
  end
end