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
    module Client
      # Virgil API client
      #
      # Contains methods for searching and managing cards.
      class VirgilClient
        # Exception raised when card is not valid
        class InvalidCardException < StandardError
          attr_reader :invalid_cards

          def initialize(invalid_cards)
            @invalid_cards = invalid_cards
          end

          def to_s
            "Cards #{@invalid_cards} are not valid"
          end
        end

        attr_accessor :access_token, :cards_service_url, :identity_service_url,
                      :cards_read_only_service_url, :ra_service_url, :card_validator

        # Constructs new VirgilClient object
        def initialize(
            access_token=nil,
            cards_service_url=Card::SERVICE_URL,
            cards_read_only_service_url=Card::READ_ONLY_SERVICE_URL,
            identity_service_url=Virgil::SDK::HighLevel::VirgilIdentity::IDENTITY_SERVICE_URL,
            ra_service_url=Card::RA_SERVICE_URL
        )
          self.access_token = access_token
          self.cards_service_url = cards_service_url
          self.cards_read_only_service_url = cards_read_only_service_url
          self.identity_service_url = identity_service_url
          self.ra_service_url = ra_service_url
        end

        # Create published new card from given attributes.
        #
        # Args:
        #   identity: Created card identity.
        #   identity_type: Created card identity type.
        #   key_pair: Key pair of the created card.
        #     Public key is stored in the card, private key is used for request signing.
        #   app_id: Application identity for authority sign.
        #   app_key: Application key for authority sign.
        #
        # Returns:
        #   Created card from server response.
        def create_card(identity, identity_type, key_pair, app_id, app_key)
          request = Virgil::SDK::Client::Requests::CreateCardRequest.new(
              identity: identity,
              identity_type: identity_type,
              scope: Client::Card::APPLICATION,
              raw_public_key: self.crypto.export_public_key(key_pair.public_key)
          )
          self.request_signer.self_sign(request, key_pair.private_key)
          self.request_signer.authority_sign(request, app_id, app_key)

          return self.create_card_from_signed_request(request)
        end


        # Create unpublished local card from given attributes.
        #
        # Args:
        #   identity: Created card identity.
        #   identity_type: Created card identity type.
        #   private_key: Private key of the created card.
        #     Public key is stored in the card, private key is used for request signing.
        #   app_id: Application identity for authority sign.
        #   app_key: Application key for authority sign.
        #   custom_data(optional): is an associative array that contains application specific
        #                          parameters(under key :data) and information about the device
        #                          on which the keypair was created(under key :device and :device_name).
        #                          example: {data: {my_key1: "my_val1", my_key2: "my_val2"}, device: "iPhone6s", device_name: "Space grey one"}
        #
        # Returns:
        #   Created local card that is not published to Virgil Security services
        def new_card(identity, identity_type, private_key, custom_data={})
          data = custom_data[:data]
          custom_data.delete(:data)
          request = Virgil::SDK::Client::Requests::CreateCardRequest.new(
              identity: identity,
              identity_type: identity_type,
              scope: Client::Card::APPLICATION,
              raw_public_key: self.crypto.extract_public_key(private_key).value,
              info: custom_data,
              data: data
          )
          self.request_signer.self_sign(request, private_key)

          return Client::Card.from_request_model(request.request_model)
        end


        # Create unpublished global card from given attributes.
        #
        # Args:
        #   identity: Created card identity.
        #   identity_type: Created card identity type.
        #   private_key: Key pair of the created card.
        #     Public key is stored in the card, private key is used for request signing.
        #   custom_data(optional): is an associative array that contains application specific
        #                          parameters(under key :data) and information about the device
        #                          on which the keypair was created(under key :device and :device_name).
        #                          example: {data: {my_key1: "my_val1", my_key2: "my_val2"}, device: "iPhone6s", device_name: "Space grey one"}
        #
        # Returns:
        #   Created global card that is not published to Virgil Security services
        def new_global_card(identity, identity_type, private_key, custom_data={})
          data = custom_data[:data]
          custom_data.delete(:data)
          request = Virgil::SDK::Client::Requests::CreateCardRequest.new(
              identity: identity,
              identity_type: identity_type,
              scope: Client::Card::GLOBAL,
              raw_public_key: self.crypto.extract_public_key(private_key).value,
              info: custom_data,
              data: data
          )
          self.request_signer.self_sign(request, private_key)

          return Client::Card.from_request_model(request.request_model)
        end


        def sign_and_publish_card(card, app_id, app_key)
          request = card.to_request
          request_signer.authority_sign(
              request,
              app_id,
              app_key
          )
          create_card_from_signed_request(request)

        end

        def publish_as_global_card(card)
          request = card.to_request
          create_card_from_signed_request(request)
        end


        # Create new card from signed creation request.
        #
        # Args:
        #   create_request: signed card creation request.
        #
        # Returns:
        #   Created card from server response.
        #
        # Raises:
        #   VirgilClient.InvalidCardException if client has validator
        #   and returned card signatures are not valid.
        def create_card_from_signed_request(create_request)
          http_request = Virgil::SDK::Client::HTTP::Request.new(
              method: Virgil::SDK::Client::HTTP::Request::POST,
              endpoint: "/#{Card::VRA_VERSION}/card",
              body: create_request.request_model
          )
          raw_response = self.ra_connection.send_request(http_request)
          card = Card.from_response(raw_response)
          self.validate_cards([card]) if self.card_validator
          card
        end

        def create_card_from_signed_request_async(create_request)
          thread = Thread.new do
            current = Thread.current
            current[:card] = create_card_from_signed_request(create_request)
          end
          thread.join
          thread[:card]
        end


        def add_relation(request)
          unless (request.is_a?(Requests::AddRelationRequest) && !request.snapshot.nil? && request.signatures.count == 1)
            raise ArgumentError.new("Request is not valid. Request must have snapshot and exactly 1 relation signature.")
          end
          http_request = Virgil::SDK::Client::HTTP::Request.new(
              method: Virgil::SDK::Client::HTTP::Request::POST,
              endpoint: "/#{Card::VC_VERSION}/card/#{request.signatures.keys.first}/collections/relations",
              body: request.request_model
          )
          raw_response = self.cards_connection.send_request(http_request)
          card = Card.from_response(raw_response)
          self.validate_cards([card]) if self.card_validator
          card
        end


        def delete_relation(request)
          unless (request.is_a?(Requests::DeleteRelationRequest) && !request.snapshot.nil? && request.signatures.count == 1)
            raise ArgumentError.new("Request is not valid. Request must have snapshot and exactly 1 relation signature.")
          end
          http_request = Virgil::SDK::Client::HTTP::Request.new(
              method: Virgil::SDK::Client::HTTP::Request::DELETE,
              endpoint: "/#{Card::VC_VERSION}/card/#{request.signatures.keys.first}/collections/relations",
              body: request.request_model
          )
          raw_response = self.cards_connection.send_request(http_request)
          card = Card.from_response(raw_response)
          self.validate_cards([card]) if self.card_validator
          card
        end


        # Revoke card by id.
        #
        # Args:
        #   card_id: id of the revoked card.
        #   reason: card revocation reason.
        #     The possible values can be found in RevokeCardRequest::Reasons class.
        #   app_id: Application identity for authority sign.
        #   app_key: Application key for authority sign.
        def revoke_card(
            card_id,
            app_id,
            app_key,
            reason=Requests::RevokeCardRequest::Reasons::Unspecified
        )
          request = Requests::RevokeCardRequest.new(
              card_id: card_id,
              reason: reason
          )
          self.request_signer.authority_sign(request, app_id, app_key)

          self.revoke_card_from_signed_request(request)
        end


        def revoke_global_card(
            card_id,
            key_pair,
            validation_token,
            reason=Requests::RevokeCardRequest::Reasons::Unspecified
        )
          request = Requests::RevokeCardRequest.new(
              card_id: card_id,
              reason: reason
          )
          request.restore(validation_token)
          self.request_signer.authority_sign(request, card_id, key_pair.private_key)
          self.revoke_card_from_signed_request(request)
        end


        # Revoke card using signed revocation request.
        #
        # Args:
        #   revocation_request: signed card revocation request.
        def revoke_card_from_signed_request(revocation_request)
          http_request = Virgil::SDK::Client::HTTP::Request.new(
              method: HTTP::Request::DELETE,
              endpoint: "/#{Card::VRA_VERSION}/card/#{revocation_request.card_id}",
              body: revocation_request.request_model
          )
          self.ra_connection.send_request(http_request)
        end

        def verify_identity(identity, identity_type)
          verify_identity_request = Requests::VerifyIdentityRequest.new(identity, identity_type)
          verify_identity_from_request(verify_identity_request)
        end

        def verify_identity_from_request(identity_request)
          http_request = Virgil::SDK::Client::HTTP::Request.new(
              method: HTTP::Request::POST,
              endpoint: "/#{Card::VRA_VERSION}/verify",
              body: identity_request.request_model
          )
          raw_response = self.identity_service_connection.send_request(http_request)
          raw_response['action_id']

        end

        def confirm_identity(action_id, confirmation_code, time_to_live, count_to_live)
          request = Requests::ConfirmIdentityRequest.new(confirmation_code, action_id, time_to_live, count_to_live)
          confirm_identity_from_request(request)
        end

        def confirm_identity_from_request(confirm_request)
          http_request = Virgil::SDK::Client::HTTP::Request.new(
              method: HTTP::Request::POST,
              endpoint: "/#{Card::VRA_VERSION}/confirm",
              body: confirm_request.request_model
          )
          raw_response = self.identity_service_connection.send_request(http_request)
          raw_response['validation_token']
        end


        # Get card by id.
        #
        # Args:
        #   card_id: id of the card to get.
        #
        # Returns:
        #   Found card from server response.
        #
        # Raises:
        #   VirgilClient::InvalidCardException if client has validator
        #   and retrieved card signatures are not valid.
        def get_card(card_id)
          # type: (str) -> Card
          http_request = Virgil::SDK::Client::HTTP::Request.new(
              method: HTTP::Request::GET,
              endpoint: "/#{Card::VC_VERSION}/card/#{card_id}",
          )
          raw_response = self.read_cards_connection.send_request(http_request)
          card = Card.from_response(raw_response)
          self.validate_cards([card]) if self.card_validator
          card
        end

        # Search cards by specified identities.
        #
        # Args:
        #   identities: identity values for search.
        #
        # Returns:
        #   Found cards from server response.
        def search_cards_by_identities(*identities)
          return self.search_cards_by_criteria(
              SearchCriteria.by_identities(identities)
          )
        end

        # Search cards by specified app bundle.
        #
        # Args:
        #   bundle: application bundle for search.
        #
        # Returns:
        #   Found cards from server response.
        def search_cards_by_app_bundle(bundle)
          return self.search_cards_by_criteria(
              SearchCriteria.by_app_bundle(bundle)
          )
        end

        # Search cards by specified search criteria.
        #
        # Args:
        #   search_criteria: constructed search criteria.
        #
        # Returns:
        #   Found cards from server response.
        #
        # Raises:
        #   VirgilClient.InvalidCardException if client has validator
        #   and cards are not valid.
        def search_cards_by_criteria(search_criteria)
          body = {identities: search_criteria.identities}
          if search_criteria.identity_type
            body[:identity_type] = search_criteria.identity_type
          end
          if search_criteria.scope == Card::GLOBAL
            body[:scope] = Card::GLOBAL
          end
          http_request = Virgil::SDK::Client::HTTP::Request.new(
              method: HTTP::Request::POST,
              endpoint: "/#{Card::VC_VERSION}/card/actions/search",
              body: body,
          )
          response = self.read_cards_connection.send_request(http_request)
          cards = response.map { |card| Card.from_response(card) }
          self.validate_cards(cards) if self.card_validator
          return cards
        end


        # Validate cards signatures.
        # Args:
        #   cards: list of cards to validate.
        #
        # Raises:
        #   VirgilClient::InvalidCardException if some cards are not valid.
        def validate_cards(cards)
          invalid_cards = cards.select { |card| !card_validator.is_valid?(card) }
          if invalid_cards.any?
            raise InvalidCardException.new(invalid_cards)
          end
        end

        # Cards service connection used for creating and revoking cards.
        def cards_connection
          @_cards_connection ||= HTTP::CardsServiceConnection.new(
              self.access_token,
              self.cards_service_url
          )
        end

        def ra_connection
          @_ra_connection ||= HTTP::CardsServiceConnection.new(
              self.access_token,
              self.ra_service_url
          )
        end
        # Cards service connection used for getting and searching cards.
        def read_cards_connection
          @_read_cards_connection = HTTP::CardsServiceConnection.new(
              self.access_token,
              self.cards_read_only_service_url
          )
        end


        def identity_service_connection
          @identity_service_connection = HTTP::CardsServiceConnection.new(
              nil,
              self.identity_service_url
          )

        end

        # Request signer for signing constructed requests.
        def request_signer
          @_request_signer ||= RequestSigner.new(self.crypto)
        end

        # Crypto library wrapper.
        def crypto
          @_crypto ||= Virgil::SDK::Cryptography::VirgilCrypto.new
        end
      end
    end
  end
end
