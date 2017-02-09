require "virgil/sdk/version"
require "virgil/crypto"

module Virgil
  module SDK
    autoload :Cryptography, 'virgil/sdk/cryptography'
    autoload :Client, 'virgil/sdk/client'
    autoload :API, 'virgil/sdk/api'
    autoload :Identity, 'virgil/sdk/identity'
  end
end
