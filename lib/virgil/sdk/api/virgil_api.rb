module Virgil
  module SDK
    module API
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
end