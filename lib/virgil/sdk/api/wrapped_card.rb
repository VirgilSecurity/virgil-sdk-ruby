module Virgil
  module SDK
    module API
      class WrappedCard
        attr_accessor :context, :card
        # private :context, :card, :context=, :card=

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
          card.export
        end


        def publish_async
          request = card.to_request
          context.client.request_signer.authority_sign(
              request,
              context.credentials.app_id,
              context.credentials.app_key(context.crypto)
          )

          self.context.client.create_card_from_signed_request_async(request)
        end


        def publish
          request = card.to_request
          context.client.request_signer.authority_sign(
              request,
              context.credentials.app_id,
              context.credentials.app_key(context.crypto)
          )

          self.card = context.client.create_card_from_signed_request(request)
        end


      end
    end
  end
end