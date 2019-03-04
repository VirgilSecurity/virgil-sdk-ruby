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
    class JwtGenerator

      # Private Key which will be used for signing
      # generated access tokens.
      # Take it on {https://dashboard.virgilsecurity.com/api-keys}
      # @return [PrivateKey]
      attr_reader :api_key

      # Key id of #api_key
      # Take it on {https://dashboard.virgilsecurity.com/api-keys}
      # @return [String]
      attr_reader :api_public_key_id

      # Application id
      # Take it on {https://dashboard.virgilsecurity.com}
      # @return [String]
      attr_reader :app_id

      # Lifetime of generated tokens in minutes
      # @return [Integer]
      attr_reader :life_time

      # An instance of [AccessTokenSigner] that is used to
      # generate token signature using #api_key
      # @return [AccessTokenSigner]
      attr_reader :access_token_signer

      # Initializes a new instance of the class
      # @param app_id [String] Application id
      #  Take it on {https://dashboard.virgilsecurity.com}
      # @param api_key [PrivateKey] Private Key which will be used for signing
      #  generated access tokens. Take it on {https://dashboard.virgilsecurity.com/api-keys}
      # @param api_public_key_id [String] Key id of #api_key.
      #  Take it on {https://dashboard.virgilsecurity.com/api-keys}
      # @param life_time [Integer] Lifetime of generated tokens in minutes
      # @param access_token_signer [AccessTokenSigner] An instance of [AccessTokenSigner]
      #  that is used to generate token signature using #api_key
      def initialize(app_id:, api_key:, api_public_key_id:, life_time:, access_token_signer:)
        @app_id = app_id
        @api_key = api_key
        @api_public_key_id = api_public_key_id
        @life_time = life_time
        @access_token_signer = access_token_signer
      end

      # Generates new JWT using specified identity and additional data.
      # @param identity [String] identity to generate with.
      # @param data [Hash] dictionary with additional data which will be kept in jwt body
      # @return new instance of [Jwt]
      def generate_token(identity, data = nil)
        raise ArgumentError, 'Identity property is mandatory' if identity.nil?
        issued_at = Time.now.utc
        expires_at = Time.at(issued_at.to_i + @life_time * 60).utc
        jwt_body = JwtBodyContent.new(app_id: @app_id,
                                      issued_at: issued_at,
                                      identity: identity,
                                      expires_at: expires_at,
                                      data: data)

        jwt_header = JwtHeaderContent.new(algorithm: @access_token_signer.algorithm,
                                          key_id: @api_public_key_id)
        unsigned_jwt = Jwt.new(header_content: jwt_header,
                               body_content: jwt_body,
                               signature_data: nil)
        jwt_bytes = Bytes.from_string(unsigned_jwt.to_s)
        signature = @access_token_signer.generate_token_signature(jwt_bytes, @api_key)
        Jwt.new(header_content: jwt_header,
                body_content: jwt_body,
                signature_data: signature)
      end

    end
  end
end