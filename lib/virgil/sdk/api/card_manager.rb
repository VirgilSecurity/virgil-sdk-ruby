module Virgil
  module SDK
    module API
      CardManager = Struct.new(:context) do

        def create(identity, owner_key)
          card = card_from_signed_create_request(
              identity: identity,
              identity_type: Client::Card::USERNAME_IDENTITY,
              scope: Client::Card::APPLICATION,
              key_pair: owner_key)


          WrappedCard.new(context: context, card: card)
        end

        def create_global(identity:, identity_type:, owner_key:)
          card = card_from_signed_create_request(
              identity: identity,
              identity_type: identity_type,
              scope: Client::Card::GLOBAL,
              key_pair: owner_key)
          WrappedCard.new(context: context, card: card)
        end


        def import(request_model_base64)
          request = Client::Requests::CreateCardRequest.import(request_model_base64)

          WrappedCard.new(
              context: self.context,
              card: Client::Card.from_request_model(request.request_model)
          )
        end


        # base64-encoded json representation of card's content_snapshot and meta

        # Create new Card from .
        # Args:
        #     base64-encoded json representation of request model
        # Returns:
        #     Card model restored from snapshot.


        private

        def card_from_signed_create_request(identity:, identity_type:, scope:, key_pair:)
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