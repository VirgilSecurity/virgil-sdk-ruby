class Context
  attr_accessor :access_token, :client, :crypto

  def initialize(access_token)
    self.access_token = access_token
    self.client = Virgil::SDK::Client::VirgilClient.new(access_token)
    self.crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
  end
#TODO credentials, cardverifiers



end