class VirgilApi
  attr_accessor :context, :keys, :cards

  def initialize(access_token)
    self.context = Context.new(access_token)
    self.keys = KeyManager.new
    self.cards = CardManager.new(self.context.client)
  end


  def initialize(context)
    self.context = context
    self.keys = KeyManager.new
    self.cards = CardManager.new(context.client)
  end


end