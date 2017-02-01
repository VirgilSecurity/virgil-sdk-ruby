module Virgil
  module SDK
    module API
      class Context
        attr_accessor :access_token, :client, :crypto, :credentials, :cards_service_url, :cards_read_only_service_url

        def initialize(access_token:, credentials:,
                       cards_service_url: Client::Card::SERVICE_URL,
                       cards_read_only_service_url: Client::Card::READ_ONLY_SERVICE_URL)
          self.access_token = access_token
          self.client = Client::VirgilClient.new(access_token, cards_service_url, cards_read_only_service_url)
          self.crypto = Cryptography::VirgilCrypto.new
          self.credentials = credentials
        end


        # def initialize(access_token)
        #   self.access_token = access_token
        #   self.client = Client::VirgilClient.new(access_token)
        #   self.crypto = Cryptography::VirgilCrypto.new
        # end
        #TODO  cardverifiers

      end
    end
  end
end