class CardManager
  attr_accessor :client
  def initialize(client)
    self.client = client
  end

  def create_global
  #TODO
  end

  def create(identity, identity_type, private_key)
    request = Virgil::SDK::Client::Requests::CreateCardRequest.new(
        identity: identity,
        identity_type: identity_type,
        raw_public_key: self.crypto.export_public_key(private_key.extract_public_key),
    )
    client.create_card(identity, identity_type,)
  end

end