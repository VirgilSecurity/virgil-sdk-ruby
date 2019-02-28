class CallbackJwtProvider
  attr_reader :obtain_access_token_proc
  def initialize(obtain_token_proc)
    # todo validate params
    @obtain_access_token_proc = obtain_token_proc
  end

  def get_token(token_context)
    # todo async?
    jwt_str = @obtain_access_token_proc.call(token_context)
    Jwt.generate(jwt_str)
  end

end