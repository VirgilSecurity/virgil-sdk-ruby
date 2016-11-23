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
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
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

module Virgil
  module SDK
    module Cryptography
      module Hashes
        # Fingerprint container class.
        #
        # Class provides methods for importing and exporting fingerprints.
        class Fingerprint
          def initialize(fingerprint_bytes)
            @fingerprint_bytes = fingerprint_bytes
          end

          # Creates new Fingerprint from hex.
          #
          # Args:
          #   fingerprint_hex: hex string of the fingerprint.
          #
          # Returns:
          #   Imported Fingerprint.
          def self.from_hex(fingerprint_hex)
            data = Crypto::Native::VirgilByteArrayUtils.hex_to_bytes(fingerprint_hex)
            return self.new(data)
          end

          # Raw fingerprint value.
          #
          #  Returns:
          #    Fingerprint bytes.
          def value
            @fingerprint_bytes
          end

          # Fingerprint data in hexadecimal.
          #
          # Returns:
          #   Hexademical fingerprint representation.
          def to_hex
            hex_data = Crypto::Native::VirgilByteArrayUtils.bytes_to_hex(value)
            return hex_data
          end
        end
      end
    end
  end
end
