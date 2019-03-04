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
    # Represents header of [Jwt]
    class JwtHeaderContent
      VIRGIL_CONTENT_TYPE = 'virgil-jwt;v=1'.freeze
      JWT_TYPE = 'JWT'.freeze

      # Signature algorithm
      # @return [String]
      attr_reader :algorithm

      # Access token type.
      # @return [String]
      attr_reader :type

      # Access token content type.
      # @return [String]
      attr_reader :content_type

      # Id of public key which is used for jwt signature verification.
      # @return [String]
      attr_reader :key_id

      # Initializes a new instance of the class
      # @param algorithm [String] signature algorithm
      # @param type [String] access token type
      # @param content_type [String] Access token content type
      # @param key_id [String] API key id. Take it from {https://dashboard.virgilsecurity.com/api-keys}
      def initialize(algorithm:, key_id:, type: JWT_TYPE, content_type: VIRGIL_CONTENT_TYPE)
        # todo validate
        @algorithm = algorithm
        @key_id = key_id
        @type = type
        @content_type = content_type
      end

      # Json representation of header content
      # @return [String]
      def to_json
        model = {
          'alg': algorithm,
          'kid': key_id,
          'typ': type,
          'cty': content_type
        }
        model.to_json
      end

      # Restore header content from json
      # @return [JwtHeaderContent]
      def self.restore_from_json(str_json)
        model = JSON.parse(str_json)
        new(algorithm: model['alg'],
            key_id: model['kid'],
            type: model['typ'],
            content_type: model['cty'])
      end
    end
  end
end