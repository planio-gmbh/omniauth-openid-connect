# -*- coding:utf-8 -*-
# frozen_string_literal: true

module OmniAuth
  module OpenIDConnect
    class Error < RuntimeError
      attr_reader :error
      def initialize error, error_message
        @error = error
        super error_message
      end
    end

    # Authorization Response に 'code' [REQUIRED] がない.
    class MissingCodeError < Error
      def initialize error_message
        super :missing_code, error_message
      end
    end

    class MissingIdTokenError < Error
      def initialize error_message
        super :missing_id_token, error_message
      end
    end
    
  end # module OpenIDConnect
end
