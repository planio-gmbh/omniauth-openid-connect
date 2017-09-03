# -*- coding:utf-8 -*-

module OmniAuth
  module OpenIDConnect
    class Error < RuntimeError; end

    # Authorization Response に 'code' [REQUIRED] がない.
    class MissingCodeError < Error; end
  end
end
