# Copyright (C) 2016 Virgil Security Inc.
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
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
require 'base64'
require 'json'

module Virgil
  module SDK
    module HighLevel

      # This class provides a list of methods that simplify the work with an array of bytes.
      VirgilBuffer = Struct.new(:bytes) do

        def initialize(bytes)

          self.class.validate_bytes_param(bytes)

          super
        end


        def self.from_bytes(bytes)

          self.validate_bytes_param(bytes)

          new(bytes)

        end


        def self.from_string(str, encoding=VirgilStringEncoding::UTF8)

          case encoding
            when VirgilStringEncoding::BASE64
              return self.from_base64(str)
            when VirgilStringEncoding::HEX
              return self.from_hex(str)
            when VirgilStringEncoding::UTF8
              return self.from_utf8(str)
            else
              ArgumentError.new("encoding is undefined")
          end

        end


        def to_string(encoding=VirgilStringEncoding::UTF8)
          case encoding
            when VirgilStringEncoding::BASE64
              return self.to_base64
            when VirgilStringEncoding::HEX
              return self.to_hex
            when VirgilStringEncoding::UTF8
              return to_s
            else
              ArgumentError.new("encoding is undefined")
          end
        end


        def to_s
          bytes.pack('c*')
        end

        # Initializes a new buffer from file.
        def self.from_file(key_file_path)
          ArgumentError.new("file_path is not valide") unless (File.exist?(key_file_path) && File.readable?(key_file_path))
          str = File.read(key_file_path)
          from_string(str)
        end


        # Initializes a new buffer from specified string, which encodes binary data as base-64 digits.
        def self.from_base64(str)
          new(Base64.decode64(str).bytes)
        end


        #Initializes a new buffer from specified string, which encodes binary data as utf-8.
        def self.from_utf8(str)
          new(str.bytes)
        end


        # Initializes a new buffer from specified string, which encodes binary data as hexadecimal digits.
        def self.from_hex(str)
          new(str.scan(/../).map { |x| x.hex })
        end


        # Converts all the bytes in current buffer to its equivalent string representation that
        # is encoded with base-64 digits.
        def to_base64
          Base64.strict_encode64(to_s)
        end


        # Decodes all the bytes in current buffer into a string.
        def to_utf8
          to_s
        end


        # Converts the numeric value of each element of a current buffer bytes to its
        # equivalent hexadecimal string representation.
        def to_hex
          to_s.each_byte.map { |b| b.to_s(16) }.join
        end


        def self.validate_buffer_param(param, param_name="buffer")
          raise ArgumentError.new("#{param_name} is not valid") unless (param.is_a?(VirgilBuffer) || param.is_a?(String))
        end

        private

        def self.validate_bytes_param(param)
          raise ArgumentError.new("bytes is not valid") if (!param.is_a?(Array) || param.empty?)
        end

      end

      module VirgilStringEncoding
        BASE64 = 1
        HEX = 2
        UTF8 = 3
      end

    end
  end
end