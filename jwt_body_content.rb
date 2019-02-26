class JwtBodyContent
  IDENTITY_PREFIX = 'identity-'.freeze
  SUBJECT_PREFIX = "virgil-"

  attr_reader :app_id, :identity, :issuer, :subject, :issued_at, :expires_at, :additional_data

  def initialize(app_id:, identity:, issued_at:, expires_at:, data:)
  # todo validate
    @app_id = app_id
    @identity = identity
    @issued_at = issued_at
    @expires_at = expires_at
    @additional_data = data
    @issuer = "#{SUBJECT_PREFIX}#{@app_id}"
    @subject = "#{IDENTITY_PREFIX}#{@identity}"
  end

end