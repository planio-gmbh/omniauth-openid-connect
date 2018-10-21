# -*- coding:utf-8 -*-

require 'simplecov'
require 'minitest/autorun'
require 'mocha/minitest'
require 'faker'
require 'active_support'

#SimpleCov.command_name 'test'
SimpleCov.start do # 最初に実行すること.
  add_filter '/test/'
end

require 'omniauth-openid-connect'
require_relative 'strategy_test_case'

OmniAuth.config.test_mode = true
OmniAuth.config.logger = Logger.new('/dev/null')
