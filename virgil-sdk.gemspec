# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'virgil/sdk/version'

Gem::Specification.new do |spec|
  spec.name          = "virgil-sdk"
  spec.version       = Virgil::SDK::VERSION
  spec.authors       = ["Dmitriy Dudkin"]
  spec.email         = ["dudkin.dmitriy@gmail.com"]

  spec.summary       = %q{Virgil keys service SDK}
  spec.description   = %q{Virgil keys service SDK}
  spec.homepage      = "https://github.com/VirgilSecurity/virgil-sdk-ruby"
  spec.licenses    = ['MIT']

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "virgil-crypto", "2.0.6"
  spec.add_runtime_dependency "faraday", "~> 0.10.0"
  spec.add_runtime_dependency "faraday_middleware", "~> 0.10.0"
  spec.add_development_dependency "bundler", "~> 1.12"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "minitest-reporters", "~> 1.1"
  spec.add_development_dependency "minitest"

end
