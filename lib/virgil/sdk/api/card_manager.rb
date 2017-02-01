module Virgil
  module SDK
    module API
      CardManager = Struct.new(:context) do
        extend SignaturesBase64

        def create(identity, key_pair)
          request = Client::Requests::CreateCardRequest.new(
              identity: identity,
              identity_type: Client::Card::USERNAME_IDENTITY,
              scope: Client::Card::APPLICATION,
              raw_public_key: key_pair.public_key.value
          )
          context.client.request_signer.self_sign(request, key_pair.private_key)
          Client::Card.from_request_model(request.request_model)
        end

        def create_global(identity:, identity_type:, owner_key:)
          request = Client::Requests::CreateCardRequest.new(
              identity: identity,
              identity_type: identity_type,
              scope: Client::Card::GLOBAL,
              raw_public_key: owner_key.public_key.value
          )
          context.client.request_signer.self_sign(request, owner_key.private_key)
          Client::Card.from_request_model(request.request_model)
        end


        # base64-encoded json representation of card's content_snapshot and meta

        # Create new Card from .
        # Args:
        #     base64-encoded json representation of request model
        # Returns:
        #     Card model restored from snapshot.

        def import(request_model_base64)
          request = Client::Requests::CreateCardRequest.new({})
          request_model = JSON.parse(Base64.decode64(request_model_base64))

          request.restore(Virgil::Crypto::Bytes.from_base64(request_model["content_snapshot"]),
                          CardManager.signatures_from_base64(request_model["meta"]["signs"]))
          Client::Card.from_request_model(request.request_model)
        end
      end
    end
  end
end