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
module Virgil
  module SDK
    module HighLevel
      class VirgilContext
        attr_reader :access_token, :client, :crypto, :credentials,
                    :cards_service_url, :cards_read_only_service_url, :ra_service_url,
                    :identity_service_url, :key_storage

        def initialize(access_token: nil, credentials: nil, key_storage_path: Cryptography::Keys::KeyStorage.default_folder,
                       cards_service_url: Client::Card::SERVICE_URL,
                       cards_read_only_service_url: Client::Card::READ_ONLY_SERVICE_URL,
                       ra_service_url: Client::Card::RA_SERVICE_URL,
                       identity_service_url: VirgilIdentity::IDENTITY_SERVICE_URL,
                       crypto: Cryptography::VirgilCrypto.new,
                       card_verifiers: []
        )
          @access_token = access_token
          @client = Client::VirgilClient.new(access_token, cards_service_url, cards_read_only_service_url, identity_service_url, ra_service_url)
          @crypto = crypto
          @credentials = credentials
          @key_storage = Cryptography::Keys::KeyStorage.new(key_storage_path)

           @client.card_validator = Client::CardValidator.new(@crypto)

          if card_verifiers.any?

            card_verifiers.each do |card_verifier|
              raise ArgumentError.new("card_verifiers is not valid") unless card_verifier.is_a? VirgilCardVerifierInfo
              @client.card_validator.add_verifier(card_verifier.card_id, @crypto.import_public_key(card_verifier.public_key_value.bytes))
            end
          end

        end
      end

    end
  end
end