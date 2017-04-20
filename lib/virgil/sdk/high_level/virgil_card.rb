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

        # An instance of the class VirgilContext that manages the VirgilApi dependencies during run time.
        attr_reader :context

        # representing card information.
        # @return [Client::Card]
        attr_reader :card

        # manages the VirgilApi dependencies during run time.
        # @return [VirgilContext]
        protected :context, :card

        # Initializes a new instance of the {VirgilCard} class.
        def initialize(context:, card:)
          @context = context
          @card = card
        end


        class AppCredentialsException < StandardError

          def to_s
            "For this action we need app_id and app_key"
          end

        end


        # unique identifier for the Virgil Card.
        # @return [String]
        def id
          card.id
        end


        # the value of current Virgil Card identity.
        # @return [String]
        def identity
          card.identity
        end


        # the identityType of current Virgil Card identity.
        # @return [String]
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
        # @return [String] base64-encoded json representation of card's content_snapshot and meta.
        # @example
        #   exported_alice_card = alice_card.export
        # @see VirgilCardManager#create How to create alice_card
        #   # AFTER EXPORT DEVELOPERS HAVE TO TRANSMIT THE VIRGIL CARD TO THE APP'S SERVER SIDE WHERE IT WILL
        #   # BE SIGNED, VALIDATED AND THEN PUBLISHED ON VIRGIL SERVICES (THIS IS NECESSARY FOR
        #   # FURTHER OPERATIONS WITH THE VIRGIL CARD).
        def export
          card.export
        end


        # Publish synchronously the card into application Virgil Services scope
        # @raise [Virgil::SDK::Client::HTTP::BaseConnection::ApiError] if access_token is invalid or
        #   Virgil Card with the same fingerprint already exists in Virgil Security services
        # @raise [AppCredentialsException] if application credentials' app_id and app_key are missing
        # @raise [NotImplementedError] if the card is Global
        # @example
        #   alice_card.publish
        # @see VirgilCardManager.import how to get alice_card
        def publish

          raise NotImplementedError.new("Current card isn't local!") unless @card.scope == Client::Card::APPLICATION
          validate_app_credentials

          @card = context.client.sign_and_publish_card(
              card,
              context.credentials.app_id,
              context.credentials.app_key(context.crypto))
        end


        # Publish synchronously the global card into application Virgil Services scope
        # @param validation_token [VirgilIdentity::ValidationToken]
        # @raise [Virgil::SDK::Client::HTTP::BaseConnection::ApiError] if
        #   Virgil Card with the same fingerprint already exists in Virgil Security services
        # @raise [NotImplementedError] if the card is Local
        def publish_as_global(validation_token)

          raise NotImplementedError.new("Current card isn't global!") unless @card.scope == Client::Card::GLOBAL

          @card.validation_token = validation_token
          @card = context.client.publish_as_global_card(card)
          @card.validation_token = validation_token
        end


        # Encrypts the specified data for current Virgil card recipient
        # @param buffer [VirgilBuffer, Crypto::Bytes, String] The data to be encrypted.
        #   It can be VirgilBuffer, utf8-String or Array of bytes
        # @return [VirgilBuffer] Encrypted data for current Virgil card recipient
        # @raise [ArgumentError] if buffer doesn't have type VirgilBuffer, String or Array of bytes
        def encrypt(buffer)

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


          VirgilBuffer.new(context.crypto.encrypt(buffer_to_encrypt.bytes, public_key))
        end


        # Initiates an identity verification process for current Card identity type. It is only working for
        # Global identity types like Email.
        # @param identity_options [VirgilIdentity::VerificationOptions] The data to be encrypted.
        # @return [VirgilIdentity::VerificationAttempt] that contains
        #   information about action and etc
        def check_identity(identity_options = nil)
          action_id = context.client.verify_identity(identity, identity_type)
          VirgilIdentity::VerificationAttempt.new(context: context, action_id: action_id,
                                                  identity: identity, identity_type: identity_type,
                                                  additional_options: identity_options)
        end


        # Verifies the specified buffer and signature with current VirgilCard recipient
        # @param buffer [VirgilBuffer, Crypto::Bytes, String] The data to be verified.
        #   It can be VirgilBuffer, utf8-encoded String or Array of bytes
        # @param signature [VirgilBuffer, Crypto::Bytes, String] The signature used to verify the data integrity.
        #   It can be VirgilBuffer, base64-encoded String or Array of bytes
        # @return [Boolean] true if signature is valid, false otherwise.
        # @raise [ArgumentError] if buffer doesn't have type VirgilBuffer, Array of bytes or utf8-encoded String
        # @raise [ArgumentError] if signature doesn't have type VirgilBuffer, base64-encoded String or Array of bytes
        def verify(buffer, signature)

          buffer_to_verify = case buffer.class.name.split("::").last
                               when 'VirgilBuffer'
                                 buffer
                               when 'String'
                                 VirgilBuffer.from_string(buffer)
                               when 'Array'
                                 VirgilBuffer.from_bytes(buffer)
                               else
                                 raise ArgumentError.new("Buffer has unsupported type")
                             end

          signature_to_verify = case signature.class.name.split("::").last
                                  when 'VirgilBuffer'
                                    signature
                                  when 'String'
                                    VirgilBuffer.from_base64(signature)
                                  when 'Array'
                                    VirgilBuffer.from_bytes(signature)
                                  else
                                    raise ArgumentError.new("Signature has unsupported type")
                                end
          context.crypto.verify(buffer_to_verify.bytes, signature_to_verify.bytes, public_key)
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