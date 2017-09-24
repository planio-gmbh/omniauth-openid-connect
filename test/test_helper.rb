# -*- coding:utf-8 -*-

require 'simplecov'
#SimpleCov.command_name 'test'
SimpleCov.start  # 最初に実行すること.

require 'minitest/autorun'
require 'mocha/mini_test'
require 'faker'
require 'active_support'
require 'omniauth-openid-connect'
require_relative 'strategy_test_case'


OmniAuth.config.test_mode = true
OmniAuth.config.logger = Logger.new('/dev/null')
