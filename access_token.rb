class AccessToken
  def identity
    raise NotImplementedError
  end

  def string_representation
    raise NotImplementedError
  end
end