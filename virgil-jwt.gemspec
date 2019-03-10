
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "virgil/jwt/version"

Gem::Specification.new do |spec|
  spec.name          = "virgil-jwt"
  spec.version       = Virgil::Jwt::VERSION
  spec.authors       = ["Vasilina Bezuglaya"]
  spec.email         = ["vbezuglaya@virgilsecurity.net"]

  spec.summary       = %q{Virgil JWT}
  spec.description   = %q{Virgil JSON Web Token to make call to Virgil Services}
  spec.homepage      = "https://github.com/VirgilSecurity/virgil-sdk-ruby/tree/jwt-v5"
  spec.license       = "BSD-3-Clause"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.16"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "minitest-reporters", "~> 1.1"
  spec.add_development_dependency 'envyable', '~> 1.2'
  spec.add_development_dependency 'virgil-crypto', '~> 3.6.2'

end
