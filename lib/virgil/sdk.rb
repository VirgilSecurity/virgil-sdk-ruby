require "virgil/sdk/version"

module Virgil
  module SDK
    autoload :Bytes, 'virgil/sdk/bytes'
    autoload :Cryptography, 'virgil/sdk/cryptography'
  end
end

require_relative 'sdk/cryptography/virgil_crypto_ruby'

Virgil::Crypto = Virgil_crypto_ruby
