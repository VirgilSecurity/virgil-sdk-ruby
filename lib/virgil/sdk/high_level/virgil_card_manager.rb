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

      # This class provides a list of methods to manage the VirgilCard entities.
      class VirgilCardManager

        # manages the VirgilApi dependencies during run time.
        # @return [VirgilContext]
        attr_reader :context
        protected :context

        # Initializes a new instance of the {VirgilCardManager} class.
        def initialize(context)
          @context = context
        end


        # AppCredentialsException raises when application credentials are missing
        # in actions where they are required.
        class AppCredentialsException < StandardError

          def to_s
            "For this action we need app_id and app_key"
          end

        end


        # AccessTokenException raises when access token is missing
        # in actions where it's required.
        class AccessTokenException < StandardError

          def to_s
            "For this action access token can't be empty"
          end

        end

        class CardArray < Array

          attr_accessor :crypto

          def initialize(array)
            @crypto = Cryptography::VirgilCrypto.new
            super
          end

          # Encrypts the specified data using recipients Public keys.
          # @param buffer [VirgilBuffer, Crypto::Bytes, String] The data to be encrypted.
          #   It can be {VirgilBuffer}, utf8 String or Array of bytes.
          # @return [VirgilBuffer] Encrypted data for current recipients Public keys.
          # @raise [ArgumentError] if buffer doesn't have type VirgilBuffer, String or Array of bytes.
          def encrypt(buffer)
            all_public_keys = self.map(&:public_key)
            buffer_to_encrypt = case buffer.class.name.split("::").last
                                  when 'VirgilBuffer'
                                    buffer
                                  when 'String'
                                    VirgilBuffer.from_string(buffer)
                                  when 'Array'
                                    VirgilBuffer.from_bytes(buffer)
                                  else
                                    raise ArgumentError.new("Buffer has unsupported type")
                                end

            VirgilBuffer.new(crypto.encrypt(buffer_to_encrypt.bytes, *all_public_keys))
          end

        end


        # Creates a new Virgil Card that is representing user's Public key and information.
        # @param identity [String] The user's identity.
        # @param owner_key [VirgilKey] The owner's Virgil key.
        # @param custom_data [Hash] is an associative array that contains application specific
        #   parameters(under key :data) and information about the device
        #   on which the keypair was created(under key :device and :device_name).
        #   example: {data: {my_key1: "my_val1", my_key2: "my_val2"}, device: "iPhone6s", device_name: "Space grey one"}.
        # @return [VirgilCard] Created unpublished Virgil Card that is representing user's Public key.
        def create(identity, owner_key, custom_data={})
          card = context.client.new_card(
              identity,
              VirgilIdentity::UNKNOWN,
              owner_key.private_key,
              custom_data
          )

          VirgilCard.new(context: context, card: card)
        end


        # Creates a new Global Virgil Card that is representing user's Public key and information.
        # @param identity [String] The user's identity.
        # @param identity_type [String] it can be VirgilIdentity::EMAIL or VirgilIdentity::APPLICATION.
        # @param owner_key [VirgilKey] The owner's Virgil key.
        # @param custom_data [Hash] is an associative array that contains application specific
        #   parameters(under key :data) and information about the device
        #   on which the keypair was created(under key :device and :device_name).
        #   example: {data: {my_key1: "my_val1", my_key2: "my_val2"}, device: "iPhone6s", device_name: "Space grey one"}.
        # @return [VirgilCard] Created unpublished Global Virgil Card that is representing user's Public key.
        def create_global(identity:, identity_type:, owner_key:, custom_data: {})
          card = context.client.new_global_card(
              identity,
              identity_type,
              owner_key.private_key,
              custom_data
          )
          VirgilCard.new(context: context, card: card)
        end


        # Publish asynchronously a card into application Virgil Services scope.
        # @param card [VirgilCard] the card to be published.
        # @raise [Virgil::SDK::Client::HTTP::BaseConnection::ApiError] if application credentials are invalid or
        #   Virgil Card with the same fingerprint already exists in Virgil Security services.
        def publish_async(card)
          card.publish_async
        end


        # Publish synchronously a card into application Virgil Services scope.
        # @param card [VirgilCard] the card to be published.
        # @raise [Client::HTTP::BaseConnection::ApiError] if application credentials are invalid or
        #    Virgil Card with the same fingerprint already exists in Virgil Security services.
        # @raise [AppCredentialsException]: if application credentials(app_key and app_id) are missing.
        def publish(card)
          card.publish
        end


        # Publish a global card into application Virgil Services scope.
        # @param card [VirgilCard] the global card to be published.
        # @raise [Client::HTTP::BaseConnection::ApiError] if VirgilIdentity Validation Token is invalid or has expired
        #   Virgil Card with the same fingerprint already exists in Virgil Security services.
        def publish_global(card, validation_token)
          card.publish_as_global(validation_token)
        end


        # Get a card from Virgil Security services by specified Card ID.
        # @param card_id [String] unique string that identifies the Card within Virgil Security services.
        # @return [VirgilCard] Found card from server response.
        # @raise [VirgilClient::InvalidCardException] if client has validator
        #   and retrieved card signatures are not valid.
        def get(card_id)
          VirgilCard.new(context: context, card: context.client.get_card(card_id))
        end


        # Find Virgil cards by specified identities in application scope.
        # @param *identities [Array<String>] the list of identities.
        # @return [Array<VirgilCard>] A list of found Virgil cards.
        # @raise [VirgilClient::InvalidCardException] if client has validator
        #   and retrieved card signatures are not valid.
        # @raise [AccessTokenException] if access token is empty.
        def find(*identities)

          raise AccessTokenException unless (context && context.access_token)

          validate_identities_param(identities)

          cards = context.client.search_cards_by_identities(*identities)
          virgil_cards = cards.map { |v| VirgilCard.new(context: context, card: v) }
          CardArray.new(virgil_cards)
        end


        # Find Global Virgil cards by specified identity type and identities.
        # @param identity_type [String] it can be VirgilIdentity::EMAIL or VirgilIdentity::APPLICATION.
        # @param *identities [Array<String>] the list of identities.
        # @return [Array<VirgilCard>] A list of found Global Virgil cards.
        # @raise [VirgilClient::InvalidCardException] if client has validator
        #   and retrieved card signatures are not valid.
        def find_global(identity_type, *identities)

          validate_identities_param(identities)

          cards = context.client.search_cards_by_criteria(
              Client::SearchCriteria.new(identities, identity_type, Client::Card::GLOBAL)
          )
          virgil_global_cards = cards.map { |v| VirgilCard.new(context: context, card: v) }
          CardArray.new(virgil_global_cards)
        end


        # Revoke a card from Virgil Services.
        # @param card [VirgilCard] the card to be revoked.
        # @raise [Client::HTTP::BaseConnection::ApiError] if the card was not published
        #   or application credentials are not valid.
        # @raise [AppCredentialsException] if application credentials are missing.
        def revoke(card)
          validate_app_credentials

          context.client.revoke_card(
              card.id,
              context.credentials.app_id,
              context.credentials.app_key(context.crypto))
        end


        # Revoke a Global card from Virgil Services.
        # @param global_card [VirgilCard] the global card to be revoked.
        # @param key_pair [VirgilKey] The Key associated with the revoking Global Card.
        # @param validation_token [VirgilIdentity::ValidationToken] is an identity token.
        # @raise [Client::HTTP::BaseConnection::ApiError] if the global card was not published.
        def revoke_global(global_card, key_pair, validation_token)
          context.client.revoke_global_card(global_card.id, key_pair, validation_token)

        end


        # Create new Card from base64-encoded json representation of card's content_snapshot and meta.
        # @param exported_card [String] base64-encoded json representation of card.
        # @return [VirgilCard] Virgil Card restored from snapshot.
        def import(exported_card)
          request = Client::Requests::CreateCardRequest.import(exported_card)

          VirgilCard.new(
              context: self.context,
              card: Client::Card.from_request_model(request.request_model)
          )
        end


        private

        def validate_identities_param(param)
          raise ArgumentError.new("identities is not valid") if (!param.is_a?(Array) || param.empty?)
        end

        def validate_app_credentials

          if !(context.credentials && context.credentials.app_id && context.credentials.app_key(context.crypto))
            raise AppCredentialsException
          end

        end
      end
    end
  end
end