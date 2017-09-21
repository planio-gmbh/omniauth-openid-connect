
require 'simplecov'

#require 'coveralls'
#Coveralls.wear!

require 'minitest/autorun'
require 'mocha/mini_test'
require 'faker'
require 'active_support'
require_relative '../lib/omniauth-openid-connect'
require_relative 'strategy_test_case'


OmniAuth.config.test_mode = true
OmniAuth.config.logger = Logger.new('/dev/null')

SimpleCov.command_name 'test'
SimpleCov.start
#Coveralls.wear!


