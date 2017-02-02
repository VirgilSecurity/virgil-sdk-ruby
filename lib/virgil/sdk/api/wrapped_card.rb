module Virgil
  module SDK
    module API
      WrappedCard = Struct.new(:context, :card) do
        def initialize(context:, card:)
          self.context = context
          self.card = card
        end

        def id
          self.card.id
        end

        def identity
          self.card.identity
        end

        def identity_type
          self.card.identity_type
        end

        def data
          self.card.data
        end

        def scope
          self.card.scope
        end

        def info
          #TODO device, device_name
          # self.data.info
        end
        # private :card, :context, :card=, :context=

        # Exports card's snapshot.
        #
        # Returns:
        #   base64-encoded json representation of card's content_snapshot and meta.
        def export
          self.card.to_request.export
        end



        def publish_async

        end

      end
    end
  end
end