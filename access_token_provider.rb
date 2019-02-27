class AccessTokenProvider
  def get_token(token_context)
    raise NotImplementedError
  end
end