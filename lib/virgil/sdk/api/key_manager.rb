module Virgil
  module SDK
    module API
      class KeyManager
        attr_accessor :crypto

        def initialize()
          self.crypto = Cryptography::VirgilCrypto.new
        end

        def generate
          crypto.generate_keys()
        end

      end
    end
  end
end
