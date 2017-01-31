module Virgil
  module SDK
    autoload :Context, 'virgil/sdk/api/context'
    autoload :KeyManager, 'virgil/sdk/api/key_manager'
    autoload :CardManager, 'virgil/sdk/api/card_manager'
    autoload :AppCredentials, 'virgil/sdk/api/app_credentials'
    class Api
      attr_accessor :context, :keys, :cards

      def initialize(access_token: nil, context: nil)
        if access_token
          self.context = Context.new(access_token)
        elsif context
          self.context = context
        end
        self.keys = KeyManager.new
        self.cards = CardManager.new(self.context)
      end
    end
  end
end