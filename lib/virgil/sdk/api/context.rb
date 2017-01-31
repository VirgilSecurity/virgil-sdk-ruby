module Virgil
  module SDK
    class Context
      attr_accessor :access_token, :client, :crypto, :credentials

      def initialize(access_token:, credentials:)
        self.access_token = access_token
        self.client = Virgil::SDK::Client::VirgilClient.new(access_token)
        self.crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
        self.credentials = credentials
      end

      # def initialize(access_token)
      #   self.access_token = access_token
      #   self.client = Virgil::SDK::Client::VirgilClient.new(access_token)
      #   self.crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
      # end
#TODO  cardverifiers

    end
  end

end