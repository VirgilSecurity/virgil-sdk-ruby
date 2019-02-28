class TokenContext
  attr_reader :operation, :identity, :service, :force_reload

  def initialize(operation:, identity:, service: nil, force_reload: false)
    @operation = operation
    @identity = identity
    @service = service
    @force_reload = force_reload
  end
end