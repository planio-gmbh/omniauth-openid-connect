# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/openid_connect/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-openid-reconnect"
  spec.version       = OmniAuth::OpenIDConnect::VERSION
  spec.authors       = ["Paul Scarrone","John Bohn"]
  spec.email         = ["paul.scarrone@gmail.com","jjbohn@gmail.com"]
  spec.summary       = %q{OpenID Connect Strategy MK2 for OmniAuth}
  spec.description   = %q{OpenID Connect Strategy MK2 for OmniAuth which is fully compliant with devise and rails and currently maintained. Derived from jjbohn's work but actively maintained}
  spec.homepage      = "https://github.com/thinkthroughmath/omniauth-openid-reconnect"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency 'activesupport', '>= 0'
  spec.add_dependency 'omniauth', '~> 1.1'
  spec.add_dependency 'openid_connect', '= 1.1.2'
  spec.add_dependency 'addressable', '~> 2.2.8' # Because there is a breaking change in 2.2.9 with the wail rails param arrays are handled
  spec.add_development_dependency 'bundler', '~> 1.5'
  spec.add_development_dependency 'minitest', '~> 5.4'
  spec.add_development_dependency 'mocha', '~> 1.1'
  spec.add_development_dependency 'guard', '~> 2.6'
  spec.add_development_dependency 'guard-minitest', '~> 2.3'
  spec.add_development_dependency 'guard-bundler', '~> 2.0'
  spec.add_development_dependency 'rake', '~> 10.3'
  spec.add_development_dependency 'simplecov', '~> 0.9'
  spec.add_development_dependency 'pry', '~> 0.10'
  spec.add_development_dependency 'coveralls', '~> 0.7'
  spec.add_development_dependency 'faker', '~> 1.4'
end
