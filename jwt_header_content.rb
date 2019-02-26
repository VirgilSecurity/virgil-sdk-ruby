class JwtHeaderContent
  VIRGIL_CONTENT_TYPE = 'virgil-jwt;v=1'.freeze
  JWT_TYPE = 'JWT'.freeze
  attr_reader :algorithm, :type, :content_type, :key_id

  def initialize(algorithm:, key_id:, type: JWT_TYPE, content_type: VIRGIL_CONTENT_TYPE)
  # todo validate
    @algorithm = algorithm
    @key_id = key_id
    @type = type
    @content_type = content_type
  end
end