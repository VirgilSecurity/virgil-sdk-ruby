class CachingJwtProvider < AccessTokenProvider
  attr_reader :obtain_access_token_proc
  def initialize(obtain_token_proc)
    # todo validate params
    @obtain_access_token_proc = obtain_token_proc
  end

  def get_token(token_context)
    # todo validate params, semaphore
    if !@jwt && (jwt.body_content.expires_at <= Time.now.utc.to_time + 5)
      jwt_str = @obtain_access_token_proc.call(token_context)
      @jwt = Jwt.generate(jwt_str)
      return @jwt
    end
  end

  private

  attr_reader :jwt
end