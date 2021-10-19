require 'singleton'

module OmniAuth
  module OpenIDConnect
    # TODO thread safety?
    class Configuration
      include Singleton

      def initialize
        @idp_config = {}
      end

      def config(issuer)
        @idp_config[issuer] ||= ::OpenIDConnect::Discovery::Provider::Config.discover!(issuer)
      end
    end
  end
end
