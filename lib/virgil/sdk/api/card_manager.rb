module Virgil
  module SDK
    CardManager = Struct.new(:context) do

      def create(identity, key_pair)
        request = Virgil::SDK::Client::Requests::CreateCardRequest.new(
            identity: identity,
            identity_type: Virgil::SDK::Client::Card::USERNAME_IDENTITY,
            scope: Virgil::SDK::Client::Card::APPLICATION,
            raw_public_key: key_pair.public_key.value
        )
        context.client.request_signer.self_sign(request, key_pair.private_key)
        Virgil::SDK::Client::Card.from_request_model(request.request_model)
      end

      def create_global(identity:, identity_type:, owner_key:)
        request = Virgil::SDK::Client::Requests::CreateCardRequest.new(
            identity: identity,
            identity_type: identity_type,
            scope: Virgil::SDK::Client::Card::GLOBAL,
            raw_public_key: owner_key.public_key.value
        )
        context.client.request_signer.self_sign(request, owner_key.private_key)
        Virgil::SDK::Client::Card.from_request_model(request.request_model)
      end


      # base64-encoded json representation of card's content_snapshot and meta

      # Create new Card from .
      # Args:
      #     base64-encoded json representation of request model
      # Returns:
      #     Card model restored from snapshot.

      def import(request_model_string)
        request = Virgil::SDK::Client::Requests::CreateCardRequest.new({})
        request_model = JSON.parse(Virgil::Crypto::Bytes.from_base64(request_model_string).to_s)
        request.restore(request_model["content_snapshot"], request_model["meta"]["signs"])
        Virgil::SDK::Client::Card.from_request_model(request.request_model)
      end
    end
  end
end