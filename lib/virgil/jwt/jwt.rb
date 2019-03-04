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
    # Implements [AccessToken] in terms of Virgil JWT.
    class Jwt < AccessToken
      # Gets a jwt body
      # @return [JwtBodyContent]
      attr_reader :body_content

      # Gets a jwt header
      # @return [JwtHeaderContent]
      attr_reader :header_content

      # Gets a digital signature of jwt
      # @return [Bytes]
      attr_reader :signature_data

      # String representation of jwt without signature.
      # It equals to:
      # Base64.urlsafe_encode64(JWT Header) + "." + Base64.urlsafe_encode64(JWT Body)
      # @return [String]
      attr_reader :unsigned_data

      #  Initializes a new instance of the [Jwt] class using specified header,
      # body and signature.
      # @param header_content [JwtHeaderContext] jwt header
      # @param body_content [JwtBodyContent] jwt body
      # @param signature_data [Bytes] jwt signature data
      def initialize(header_content:, body_content:, signature_data:)
        @header_content = header_content
        @body_content = body_content
        @signature_data = signature_data
        @string_representation = "#{header_base64}.#{body_base64}"
        @unsigned_data = Bytes.from_string(@string_representation)
        @string_representation += ".#{signature_base64}" unless @signature_data.nil?
      end

      #  Initializes a new instance of the [Jwt] class using
      # its string representation
      # @param jwt_str [String] string representation of signed jwt.
      # It must be equal to:
      #  Base64.urlsafe_encode64(jwt_header.to_base64) + "."
      # + Base64.urlsafe_encode64(JWT Body) "."
      # + Base64.urlsafe_encode64(Jwt Signature).
      # @return [Jwt]
      def self.from(jwt_str)
        begin
          parts = jwt_str.split('.')
          raise ArgumentError unless parts.size == 3
          signature_data = Bytes.new(Base64.urlsafe_decode64(parts[2]).bytes)
          new(header_content: parse_header_content(parts[0]),
              body_content: parse_body_content(parts[1]),
              signature_data: signature_data)
        rescue StandardError
          raise ArgumentError, 'Wrong JWT format.'
        end

      end

      # String representation of jwt.
      # @return [String]
      def to_s
        @string_representation
      end

      # Whether or not token is expired.
      # @return [TrueClass]
      def expired?
        Time.now.utc >= @body_content.expires_at
      end

      private

      attr_reader :string_representation

      def self.parse_body_content(str)
        body_json =  Base64.urlsafe_decode64(str)
        JwtBodyContent.restore_from_json(body_json)
      end

      def self.parse_header_content(str)
        header_json = Base64.urlsafe_decode64(str)
        JwtHeaderContent.restore_from_json(header_json)
      end

      def header_base64
        Base64.urlsafe_encode64(@header_content.to_json, padding: false)
      end

      def body_base64
        Base64.urlsafe_encode64(@body_content.to_json, padding: false)
      end

      def signature_base64
        Base64.urlsafe_encode64(@signature_data.to_s, padding: false)
      end
    end
  end
end