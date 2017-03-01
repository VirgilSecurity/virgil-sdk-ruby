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
      # A Virgil Card is the main entity of the Virgil Security services, it includes an information
      # about the user and his public key. The Virgil Card identifies the user by one of his available
      # types, such as an email, a phone number, etc.
      class VirgilCard
        attr_reader :context, :card
        protected :context, :card

        def initialize(context:, card:)
          @context = context
          @card = card
        end


        class AppCredentialsException < StandardError

          def to_s
            "For this operation we need app_id and app_key"
          end

        end


        def id
          card.id
        end


        def identity
          card.identity
        end


        def identity_type
          card.identity_type
        end


        def data
          card.data
        end


        def scope
          card.scope
        end

        def public_key
          context.crypto.import_public_key(card.public_key)
        end


        def device
          card.device
        end


        def device_name
          card.device_name
        end


        # Exports card's snapshot.
        #
        # Returns:
        #   base64-encoded json representation of card's content_snapshot and meta.
        def export
          card.export
        end


        # Publish synchronously the card into application Virgil Services scope
        # Raises:
        # Virgil::SDK::Client::HTTP::BaseConnection::ApiError if access_token is invalid or
        #  Virgil Card with the same fingerprint already exists in Virgil Security services
        # AppCredentialsException:  For this operation we need app_id and app_key
        #  if application credentials is missing
        def publish

          raise NotImplementedError.new("Current card isn't local!") unless @card.scope == Client::Card::APPLICATION
          validate_app_credentials

          @card = context.client.sign_and_publish_card(
              card,
              context.credentials.app_id,
              context.credentials.app_key(context.crypto))
        end


        # Publish synchronously the global card into application Virgil Services scope
        # Raises:
        # Virgil Card with the same fingerprint already exists in Virgil Security services
        def publish_as_global(validation_token)

          raise NotImplementedError.new("Current card isn't global!") unless @card.scope == Client::Card::GLOBAL

          @card.validation_token = validation_token
          @card = context.client.publish_as_global_card(card)
          @card.validation_token = validation_token
        end


        # Encrypts the specified data for current Virgil card recipient
        #
        # Args:
        #   buffer: The data to be encrypted.
        #
        # Returns:
        #   Encrypted data for current Virgil card recipient
        #
        # Raises:
        #   ArgumentError: buffer is not valid if buffer doesn't have type VirgilBuffer or String
        def encrypt(buffer)

          VirgilBuffer.validate_buffer_param(buffer)

          VirgilBuffer.new(context.crypto.encrypt(buffer.bytes, public_key))
        end


        # Initiates an identity verification process for current Card indentity type. It is only working for
        #  Global identity types like Email.
        #
        # Args:
        #   identity_options: The data to be encrypted.
        #
        # Returns:
        #   An instance of VirgilIdentity::VerificationAttempt that contains
        #   information about operation etc
        def check_identity(identity_options = nil)
          action_id = context.client.verify_identity(identity, identity_type)
          VirgilIdentity::VerificationAttempt.new(context: context, action_id: action_id,
                                                  identity: identity, identity_type: identity_type,
                                                  additional_options: identity_options)
        end


        #  Verifies the specified buffer and signature with current VirgilCard recipient
        #
        # Args:
        #   buffer: The data to be verified.
        #   signature: The signature used to verify the data integrity.
        #
        # Returns:
        #    true if signature is valid, false otherwise.
        #
        # Raises:
        #   ArgumentError: buffer is not valid if buffer doesn't have type VirgilBuffer or String
        #   ArgumentError: buffer is not valid if signature doesn't have type VirgilBuffer or String
        def verify(buffer, signature)
          VirgilBuffer.validate_buffer_param(buffer)
          VirgilBuffer.validate_buffer_param(signature, "signature")
          context.crypto.verify(buffer.bytes, signature.bytes, public_key)
        end

        private

        def validate_app_credentials

          if !(context.credentials && context.credentials.app_id && context.credentials.app_key(context.crypto))
            raise AppCredentialsException
          end

        end
      end

    end
  end
end