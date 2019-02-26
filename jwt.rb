module Virgil
  module SDK
  class Jwt < AccessToken
    attr_reader :body_content, :header_content, :signature_data
    def initialize(header_content:, body_content:, signature_data:)
      # todo validate params
      @header_content = header_content
      @body_content = body_content
      @signature_data = signature_data
      @string_representation = "#{header_base64}.#{body_base64}"
      @unsigned_data = Bytes.from_string(@string_representation)
      @string_representation += ".#{signature_base64}" unless @signature_data.nil?
    end

    def self.generate(jwt_str)
      # todo validate params
      parts = jwt_str.split('.')
      raise ArgumentError, 'Wrong JWT format.' unless parts.size != 3

      begin
        header_json = Bytes.from_base64(parts[0]).to_s
        header_content = JSON.parse(header_json)
        signature_data = Bytes.from_base64(parts[2])

        new(header_content, parse_body_content(parts[1]), signature_data)
      rescue Error
        raise ArgumentError, 'Wrong JWT format.'
      end

    end

    def to_s
      @string_representation
    end

    private

    attr_reader :unsigned_data, :string_representation

    def self.parse_body_content(str)
      body_json = Bytes.from_base64(str).to_s
      body_content = JSON.parse(body_json)
      body_content.app_id = body_content.issuer.gsub(JwtBodyContent::SUBJECT_PREFIX, '')
      body_content.identity = body_content.subject.gsub(JwtBodyContent::IDENTITY_PREFIX, '')
      body_content
    end

    def header_base64
      Bytes.from_string(@header_content.to_json).to_base64
    end

    def body_base64
      Bytes.from_string(@body_content.to_json).to_base64
    end

    def signature_base64
      Bytes.new(@signature_data).to_base64
    end
  end
  end
end