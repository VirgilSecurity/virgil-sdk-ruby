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
      class VirgilCardManager
        attr_reader :context
        protected :context

        def initialize(context)
          @context = context
        end


        class AppCredentialsException < StandardError

          def to_s
            "For this operation we need app_id and app_key"
          end

        end

        class AccessTokenException < StandardError

          def to_s
            "For this operation access token can't be empty"
          end

        end

        class CardArray < Array

          attr_accessor :crypto

          def initialize(array)
            @crypto = Cryptography::VirgilCrypto.new
            super
          end

          # Encrypts the specified data using recipients Public keys.
          #
          # Args:
          #   buffer: The data to be encrypted.
          #
          # Returns:
          #   Encrypted data for current recipients Public keys
          #
          # Raises:
          #   ArgumentError: buffer is not valid if buffer doesn't have type VirgilBuffer or String
          def encrypt(buffer)

            raise ArgumentError.new("buffer is not valid") if !(buffer.is_a?(VirgilBuffer) || buffer.is_a?(String))

            all_public_keys = self.map(&:public_key)
            VirgilBuffer.new(crypto.encrypt(buffer.bytes, *all_public_keys))
          end

        end


        # Creates a new Virgil Card that is representing user's Public key and information
        #
        # Args:
        #   identity: The user's identity.
        #   owner_key: The owner's Virgil key.
        #   custom_data(optional): is an associative array that contains application specific
        #                          parameters(under key :data) and information about the device
        #                          on which the keypair was created(under key :device and :device_name).
        #                          example: {data: {my_key1: "my_val1", my_key2: "my_val2"}, device: "iPhone6s", device_name: "Space grey one"}
        #
        # Returns:
        #   Created unpublished Virgil Card that is representing user's Public key
        def create(identity, owner_key, custom_data={})
          card = context.client.new_card(
              identity,
              VirgilIdentity::USERNAME,
              owner_key.private_key,
              custom_data
          )

          VirgilCard.new(context: context, card: card)
        end


        # Creates a new Global Virgil Card that is representing user's Public key and information
        #
        # Args:
        #   identity: The user's identity.
        #   owner_key: The owner's Virgil key.
        #   custom_data(optional): is an associative array that contains application specific
        #                          parameters(under key :data) and information about the device
        #                          on which the keypair was created(under key :device and :device_name).
        #                          example: {data: {my_key1: "my_val1", my_key2: "my_val2"}, device: "iPhone6s", device_name: "Space grey one"}
        #
        # Returns:
        #   Created unpublished Global Virgil Card that is representing user's Public key
        def create_global(identity:, identity_type:, owner_key:, custom_data: {})
          card = context.client.new_global_card(
              identity,
              identity_type,
              owner_key.private_key,
              custom_data
          )
          VirgilCard.new(context: context, card: card)
        end


        # Publish asynchronously a card into application Virgil Services scope
        # Args:
        #     card: the card to be published
        # Raises:
        # Virgil::SDK::Client::HTTP::BaseConnection::ApiError if application credentials is invalid or
        # Virgil Card with the same fingerprint already exists in Virgil Security services
        def publish_async(card)
          card.publish_async
        end


        # Publish synchronously a card into application Virgil Services scope
        # Args:
        #     card: the card to be published
        # Raises:
        # Client::HTTP::BaseConnection::ApiError if application credentials is invalid or
        # Virgil Card with the same fingerprint already exists in Virgil Security services
        def publish(card)
          card.publish
        end


        # Publish a global card into application Virgil Services scope
        # Args:
        #     card: the global card to be published
        # Raises:
        # Client::HTTP::BaseConnection::ApiError if VirgilIdentity Validation Token is invalid or has expired
        # Virgil Card with the same fingerprint already exists in Virgil Security services
        def publish_global(card, validation_token)
          card.publish_as_global(validation_token)
        end


        # Get a card from Virgil Security services by specified Card ID.
        #
        # Args:
        #   card_id: unique string that identifies the Card within Virgil Security services
        #
        # Returns:
        #   Found card from server response.
        #
        # Raises:
        #   VirgilClient::InvalidCardException if client has validator
        #    and retrieved card signatures are not valid.
        def get(card_id)
          VirgilCard.new(context: context, card: context.client.get_card(card_id))
        end


        # Find Virgil cards by specified identities in application scope.
        #
        # Args:
        #   identities: the list of identities
        #
        # Returns:
        #   A list of found Virgil cards
        #
        # Raises:
        #   VirgilClient::InvalidCardException if client has validator
        #   and retrieved card signatures are not valid.
        #   AccessTokenException:: "For this operation access token can't be empty"
        #
        def find(*identities)

          raise AccessTokenException unless (context && context.access_token)

          validate_identities_param(identities)

          cards = context.client.search_cards_by_identities(*identities)
          virgil_cards = cards.map { |v| VirgilCard.new(context: context, card: v) }
          CardArray.new(virgil_cards)
        end


        def find_global(identity_type, *identities)

          validate_identities_param(identities)

          cards = context.client.search_cards_by_criteria(
              Client::SearchCriteria.new(identities, identity_type, Client::Card::GLOBAL)
          )
          virgil_global_cards = cards.map { |v| VirgilCard.new(context: context, card: v) }
          CardArray.new(virgil_global_cards)
        end


        # Revoke a card from Virgil Services
        #
        # Args:
        #   card: the card to be revoked
        #
        # Raises:
        #   Client::HTTP::BaseConnection::ApiError if the card was not published
        #   or application credentials is not valid.
        #   AppCredentialsException:  For this operation we need app_id and app_key
        #    if application credentials are missing

        def revoke(card)
          validate_app_credentials

          context.client.revoke_card(
              card.id,
              context.credentials.app_id,
              context.credentials.app_key(context.crypto))
        end


        # Revoke a global card from Virgil Services
        #
        # Args:
        #   card: the global card to be revoked
        #
        # Raises:
        #   Client::HTTP::BaseConnection::ApiError if the global card was not published
        #   Client::HTTP::BaseConnection::ApiError if VirgilIdentity Validation Token is invalid or has expired
        def revoke_global(global_card, key_pair, validation_token)
          context.client.revoke_global_card(global_card.id, key_pair, validation_token)

        end


        # Create new Card from base64-encoded json representation of card's content_snapshot and meta
        #
        # Args:
        #     base64-encoded json representation of card
        #
        # Returns:
        #     Virgil Card restored from snapshot.

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