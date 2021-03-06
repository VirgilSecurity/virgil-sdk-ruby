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

      # The VirgilContext class manages the VirgilApi dependencies during run time.
      # It also contains a list of properties that uses to configure the high-level components.
      class VirgilContext

        # Provides an authenticated secure access to the
        # Virgil Security services. The access token also allows the API to associate
        # your app requests with your Virgil Security developer’s account.
        # @return [String]
        attr_reader :access_token

        # Virgil Security services client.
        # @return [Client::VirgilClient]
        attr_reader :client

        # crypto API that represents a set of methods for dealing with low-level cryptographic primitives and
        # algorithms.
        # @return [VirgilCrypto]
        attr_reader :crypto

        # Application authentication credentials.
        # @return [VirgilAppCredentials]
        attr_reader :credentials

        # Cryptographic keys storage.
        # @return [Cryptography::Keys::KeyStorage]
        attr_reader :key_storage

        # indicates whether the Cards be verified with built in verifiers or not.
        # @return [Boolean]
        attr_reader :use_built_in_verifiers


        # Initializes a new instance of the {VirgilContext} class.
        # @example Initializes a new instance with disabled built in verifiers
        #   VirgilContext.new(
        #       access_token: "[YOUR_ACCESS_TOKEN_HERE]",
        #       credentials: VirgilAppCredentials.new(
        #           app_id: "[YOUR_APP_ID_HERE]",
        #           app_key_data: VirgilBuffer.from_file("[YOUR_APP_KEY_PATH_HERE]"),
        #           app_key_password: "[YOUR_APP_KEY_PASSWORD_HERE]"),
        #           use_built_in_verifiers: false
        #   )
        def initialize(access_token: nil, credentials: nil, key_storage_path: Cryptography::Keys::KeyStorage.default_folder,
                       cards_service_url: Client::Card::SERVICE_URL,
                       cards_read_only_service_url: Client::Card::READ_ONLY_SERVICE_URL,
                       ra_service_url: Client::Card::RA_SERVICE_URL,
                       identity_service_url: VirgilIdentity::IDENTITY_SERVICE_URL,
                       crypto: Cryptography::VirgilCrypto.new,
                       card_verifiers: [],
                       use_built_in_verifiers: true
        )
          @access_token = access_token
          @client = Client::VirgilClient.new(access_token, cards_service_url, cards_read_only_service_url, identity_service_url, ra_service_url)
          @crypto = crypto
          @credentials = credentials
          @key_storage = Cryptography::Keys::KeyStorage.new(key_storage_path)
          @use_built_in_verifiers = use_built_in_verifiers

          validator = Client::CardValidator.new(@crypto)
          validator.add_default_verifiers if @use_built_in_verifiers
          @client.card_validator = validator

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