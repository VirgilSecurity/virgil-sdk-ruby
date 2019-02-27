class ConstAccessTokenProvider
  def initialize(token)
    # todo validate params
    @access_token = token
  end

  def get_token(token_context)
    access_token
  end

  private

  attr_reader :access_token
end