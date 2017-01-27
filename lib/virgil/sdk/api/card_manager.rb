CardManager = Struct.new(:context) do

  def create(identity, key_pair)
    request = Virgil::SDK::Client::Requests::CreateCardRequest.new(
        identity: identity,
        identity_type: "username",
        raw_public_key: key_pair.public_key.value
    )
    context.client.request_signer.self_sign(request, key_pair.private_key)
    context.client.create_card_from_signed_request(request)
  end

  def create_global(identity:, identity_type:, owner_key:)
    request = Virgil::SDK::Client::Requests::CreateCardRequest.new(
        identity: identity,
        identity_type: identity_type,
        scope: Card::GLOBAL,
        raw_public_key: owner_key.public_key.value
    )
    context.client.request_signer.self_sign(request, owner_key.private_key)
    context.client.create_card_from_signed_request(request)
  end
end
