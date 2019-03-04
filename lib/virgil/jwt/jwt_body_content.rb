# Copyright (C) 2015-2019 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   (1) Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
#   (2) Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
#   (3) Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, bytes, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

module Virgil
  module Jwt
    #  Represents content of [Jwt]
    class JwtBodyContent
      IDENTITY_PREFIX = 'identity-'.freeze
      SUBJECT_PREFIX = 'virgil-'.freeze

      # Jwt application id.
      # @return [String]
      attr_reader :app_id

      # Jwt identity.
      # @return [String]
      attr_reader :identity

      # Jwt issuer.
      # @return [String]
      attr_reader :issuer

      # Jwt subject.
      # @return [String]
      attr_reader :subject

      # When Jwt was issued.
      # @return [Time]
      attr_reader :issued_at

      # When Jwt will expire.
      # @return [Time]
      attr_reader :expires_at

      # Jwt additional data.
      # @return [Hash]
      attr_reader :additional_data

      # Initializes a new instance of the class
      # @param app_id [String] Application ID. Take it from {https://dashboard.virgilsecurity.com}
      # @param identity [String] identity (must be equal to RawSignedModel identity when publishing card)
      # @param issued_at [Time] issued data
      # @param expires_at [Time] expiration date
      # @param data [Hash] hash with additional data
      def initialize(app_id:, identity:, issued_at:, expires_at:, data:)
        @app_id = app_id
        @identity = identity
        @issued_at = issued_at
        @expires_at = expires_at
        @additional_data = data
        @issuer = "#{SUBJECT_PREFIX}#{@app_id}"
        @subject = "#{IDENTITY_PREFIX}#{@identity}"
      end

      # Json representation of body content
      # @return [String]
      def to_json
        model = {
          'iss': issuer,
          'sub': subject,
          'iat': issued_at.to_i,
          'exp': expires_at.to_i,
          'ada': additional_data}
        model.to_json
      end

      # Restore body content from json
      # @return [JwtBodyContent]
      def self.restore_from_json(str_json)
        model = JSON.parse(str_json)
        new(app_id: model['iss'].gsub(JwtBodyContent::SUBJECT_PREFIX, ''),
            identity: model['sub'].gsub(JwtBodyContent::IDENTITY_PREFIX, ''),
            issued_at: Time.at(model['iat']).utc,
            expires_at: Time.at(model['exp']).utc,
            data: model['ada'])
      end
    end
  end
end