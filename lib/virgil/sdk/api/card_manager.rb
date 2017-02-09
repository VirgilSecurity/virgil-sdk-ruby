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
    module API
      class CardManager
        attr_reader :context
        protected :context

        def initialize(context)
          @context = context
        end


        # Creates a new Virgil Card that is representing user's Public key and information
        #
        # Args:
        #   identity: The user's identity.
        #   owner_key: The owner's Virgil key.
        #
        # Returns:
        #   Created unpublished Virgil Card that is representing user's Public key
        def create(identity, owner_key)
          card = context.client.new_card(
              identity,
              Client::Card::USERNAME_IDENTITY,
              owner_key,
              context.credentials.app_id,
              context.credentials.app_key(context.crypto)
          )

          VirgilCard.new(context: context, card: card)
        end

        # Creates a new Global Virgil Card that is representing user's Public key and information
        #
        # Args:
        #   identity: The user's identity.
        #   owner_key: The owner's Virgil key.
        #
        # Returns:
        #   Created unpublished Global Virgil Card that is representing user's Public key
        def create_global(identity:, identity_type:, owner_key:)
          card = context.client.new_global_card(
              identity,
              identity_type,
              owner_key
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
        #   and retrieved card signatures are not valid.
        def get(card_id)
          VirgilCard.new(context: context, card: context.client.get_card(card_id))
        end


        # Revoke a card from Virgil Services
        #
        # Args:
        #   card: the card to be revoked
        #
        # Raises:
        #   Virgil::SDK::Client::HTTP::BaseConnection::ApiError if the card was not published
        #   or application credentials is not valid.
        def revoke(card)
          context.client.revoke_card(
              card.id,
              context.credentials.app_id,
              context.credentials.app_key(context.crypto))
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


      end
    end
  end
end