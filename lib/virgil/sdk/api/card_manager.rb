module Virgil
  module SDK
    module API
      CardManager = Struct.new(:context) do

        def create(identity, owner_key)
          card = create_card(
              identity: identity,
              identity_type: Client::Card::USERNAME_IDENTITY,
              scope: Client::Card::APPLICATION,
              key_pair: owner_key)

          WrappedCard.new(context: context, card: card)
        end

        def create_global(identity:, identity_type:, owner_key:)
          card = create_card(
              identity: identity,
              identity_type: identity_type,
              scope: Client::Card::GLOBAL,
              key_pair: owner_key)

          WrappedCard.new(context: context, card: card)
        end

        def publish_async

        end




        # Create new Card from base64-encoded json representation of card's content_snapshot and meta
        # Args:
        #     base64-encoded json representation of card
        # Returns:
        #     Wrapped card model restored from snapshot.

        def import(exported_card)
          request = Client::Requests::CreateCardRequest.import(exported_card)

          WrappedCard.new(
              context: self.context,
              card: Client::Card.from_request_model(request.request_model)
          )
        end

        private
        def create_card(identity:, identity_type:, scope:, key_pair:)
          request = Client::Requests::CreateCardRequest.new(
              identity: identity,
              identity_type: identity_type,
              scope: scope,
              raw_public_key: key_pair.public_key.value
          )
          context.client.request_signer.self_sign(request, key_pair.private_key)
          Client::Card.from_request_model(request.request_model)
        end


      end
    end
  end
end