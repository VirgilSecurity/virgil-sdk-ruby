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
    class JwtVerifier

      # @return [AccessTokenSigner] that is used to
      # verify token signature.
      attr_reader :access_token_signer

      #  Public Key which should be used to verify signatures
      # @return [PublicKey]
      attr_reader :api_public_key

      # Id of public key which should be used to verify signatures
      # @return [String]
      attr_reader :api_public_key_id

      # Initializes a new instance of the class
      # @param access_token_signer [AccessTokenSigner]
      # @param api_public_key [PublicKey]
      # @param api_public_key_id [String]
      def initialize(access_token_signer:, api_public_key:, api_public_key_id:)
        @access_token_signer = access_token_signer
        @api_public_key = api_public_key
        @api_public_key_id = api_public_key_id
      end

      # Verifies specified token.
      # @param jwt [Jwt] token to be virefied.
      # @return true if token is verified, otherwise false.
      def verify_token(jwt)
        if jwt.header_content.key_id != @api_public_key_id ||
           jwt.header_content.algorithm != @access_token_signer.algorithm ||
           jwt.header_content.content_type != JwtHeaderContent::VIRGIL_CONTENT_TYPE ||
           jwt.header_content.type != JwtHeaderContent::JWT_TYPE
          return false
        end

        @access_token_signer.verify_token_signature(jwt.signature_data,
                                                    jwt.unsigned_data,
                                                    api_public_key)
      end
    end
  end
end