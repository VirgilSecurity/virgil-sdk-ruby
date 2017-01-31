module Virgil
  module SDK
    class KeyManager
      attr_accessor :crypto

      def initialize()
        self.crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
      end

      def generate
        crypto.generate_keys()
      end

    end
  end
end