# -*- coding:utf-8 -*-

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/openid_connect/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-openid-connect"
  spec.version       = OmniAuth::OpenIDConnect::VERSION
  spec.authors       = ["Paul Scarrone","John Bohn"]
  spec.email         = ["paul.scarrone@gmail.com","jjbohn@gmail.com"]
  spec.summary       = %q{OpenID Connect Strategy MK2 for OmniAuth}
  spec.description   = %q{OpenID Connect Strategy MK2 for OmniAuth which is fully compliant with devise and rails and currently maintained. Derived from jjbohn's work which is not actively maintained}
  spec.homepage      = "https://github.com/hhorikawa/omniauth-openid-connect"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency 'activesupport', '>= 0'
  spec.add_dependency 'omniauth', '~> 1.2'
  spec.add_dependency 'openid_connect', '~> 1.1.2'
  spec.add_dependency 'addressable', '~> 2.4.0' # 2.5から依存パッケージが増加.
  spec.add_dependency 'jwt', '= 1.5.2'
  spec.add_development_dependency "bundler", "~> 1.5"
  spec.add_development_dependency "minitest"
  spec.add_development_dependency "mocha"
  spec.add_development_dependency "guard"
  spec.add_development_dependency "guard-minitest"
  spec.add_development_dependency "guard-bundler"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "simplecov"
  spec.add_development_dependency "pry"
  spec.add_development_dependency "coveralls"
  spec.add_development_dependency "faker"
end
