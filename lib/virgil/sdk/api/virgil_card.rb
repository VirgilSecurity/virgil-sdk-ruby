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
      class VirgilCard
        attr_accessor :context, :card
        # private :context, :card, :context=, :card=

        def initialize(context:, card:)
          self.context = context
          self.card = card
        end

        def id
          self.card.id
        end

        def identity
          self.card.identity
        end

        def identity_type
          self.card.identity_type
        end

        def data
          self.card.data
        end

        def scope
          self.card.scope
        end

        def info
          #TODO device, device_name
          # self.data.info
        end

        # private :card, :context, :card=, :context=

        # Exports card's snapshot.
        #
        # Returns:
        #   base64-encoded json representation of card's content_snapshot and meta.
        def export
          card.export
        end

        # Publish asynchronously the card into application Virgil Services scope
        # Raises:
        # Virgil::SDK::Client::HTTP::BaseConnection::ApiError if access_token is invalid or
        # Virgil Card with the same fingerprint already exists in Virgil Security services
        def publish_async
          request = authority_signed_request
          self.card = self.context.client.create_card_from_signed_request_async(request)
        end


        # Publish synchronously the card into application Virgil Services scope
        # Raises:
        # Virgil::SDK::Client::HTTP::BaseConnection::ApiError if access_token is invalid or
        # Virgil Card with the same fingerprint already exists in Virgil Security services
        def publish
          request = authority_signed_request
          self.card = context.client.create_card_from_signed_request(request)
        end

        def authority_signed_request
          request = card.to_request
          context.client.request_signer.authority_sign(
              request,
              context.credentials.app_id,
              context.credentials.app_key(context.crypto)
          )
          request
        end


      end
    end
  end
end