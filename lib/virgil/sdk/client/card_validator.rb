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
    module Client
      # Class used for cards signatures validation.
      class CardValidator
        SERVICE_CARD_ID = '3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853'
        SERVICE_PUBLIC_KEY = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQVlSNTAx'\
           'a1YxdFVuZTJ1T2RrdzRrRXJSUmJKcmMyU3lhejVWMWZ1RytyVnM9Ci0tLS0tRU5E'\
           'IFBVQkxJQyBLRVktLS0tLQo='

        attr_reader :crypto, :verifiers

        def initialize(crypto)
          @crypto = crypto
          @public_key_bytes = Crypto::Bytes.from_base64(SERVICE_PUBLIC_KEY)
          @public_key = crypto.import_public_key(@public_key_bytes)
          @verifiers = {
              SERVICE_CARD_ID => @public_key
          }
        end

        #  Add signature verifier.
        #
        #  Args:
        #      card_id: Card identifier
        #      public_key: Public key used for signature verification.
        def add_verifier(card_id, public_key)
          @verifiers[card_id] = public_key
        end

        # Validates Card using verifiers.
        #
        # Args:
        #     card: Card for validation.
        # Returns:
        #     True if card signatures are valid, false otherwise.
        def is_valid?(card)

          return true if (card.version == '3.0')

          if (card.nil? || !card.is_a?(Card) || card.snapshot.nil? || (card.signatures.nil? || card.signatures.empty?))
            return false
          end

          # add self signature verifier
          fingerprint = self.crypto.calculate_fingerprint(
              Crypto::Bytes.from_string(card.snapshot)
          )
          fingerprint_hex = fingerprint.to_hex
          return false if fingerprint_hex != card.id

          verifiers = self.verifiers.clone
          card_public_key = self.crypto.import_public_key(card.public_key)
          verifiers[fingerprint_hex] = card_public_key

          verifiers.each do |id, key|
            unless card.signatures.has_key?(id)
              return false
            end
            is_valid = self.crypto.verify(
                fingerprint.value,
                Crypto::Bytes.from_base64(card.signatures[id]),
                key
            )
            return false unless is_valid
          end
          true
        end
      end
    end
  end
end
