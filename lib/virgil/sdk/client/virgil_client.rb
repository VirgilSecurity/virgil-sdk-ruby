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

      # This class represents a Virgil Security services client and contains
      # all methods to interaction with server.
      # @attr [String] access_token Provides an authenticated secure access to the
      #   Virgil Security services.
      # @attr [String] cards_service_url  Virgil Cards service url
      # @attr [String] identity_service_url  Virgil Identity service url
      # @attr [String] cards_read_only_service_url Virgil Cards RO service url
      # @attr [String] ra_service_url Virgil RA service url
      # @attr [CardValidator] card_validator
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


        # Initializes a new instance of the {VirgilClient} class.
        def initialize(
            access_token=nil,
            cards_service_url=Card::SERVICE_URL,
            cards_read_only_service_url=Card::READ_ONLY_SERVICE_URL,
            identity_service_url=HighLevel::VirgilIdentity::IDENTITY_SERVICE_URL,
            ra_service_url=Card::RA_SERVICE_URL
        )
          self.access_token = access_token
          self.cards_service_url = cards_service_url
          self.cards_read_only_service_url = cards_read_only_service_url
          self.identity_service_url = identity_service_url
          self.ra_service_url = ra_service_url
        end


        # Create published new card from given attributes.
        # @param identity [String] Created card identity.
        # @param identity_type [String] Created card identity type.
        # @param key_pair [Cryptography::Keys::KeyPair] Key pair of the created card.
        #   Public key is stored in the card, private key is used for request signing.
        # @param app_id [String] Application identity for authority sign.
        # @param app_key [Cryptography::Keys::PrivateKey] Application key for authority sign.
        # @return [Card] Created card from server response.
        # @example Create published card
        #   client = Client::VirgilClient.new("[YOUR_ACCESS_TOKEN_HERE]")
        #   crypto = Cryptography::VirgilCrypto.new
        #   app_key_password = "[YOUR_APP_KEY_PASSWORD_HERE]"
        #   app_id = "[YOUR_APP_ID_HERE]"
        #   app_key_data = Virgil::Crypto::Bytes.from_string(File.read("[YOUR_APP_KEY_PATH_HERE]"))
        #
        #   app_key = crypto.import_private_key(app_key_data, app_key_password)
        #   alice_keys = crypto.generate_keys()
        #
        #   alice_card = client.create_card(
        #       "alice",
        #       "unknown",
        #       alice_keys,
        #       app_id,
        #       app_key
        #   )
        def create_card(identity, identity_type, key_pair, app_id, app_key)
          request = Client::Requests::CreateCardRequest.new(
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
        # @param identity [String] Created card identity.
        # @param identity_type [String] Created card identity type.
        # @param private_key [Cryptography::Keys::PrivateKey] Private key of the created card.
        # @param custom_data [Hash] contains application specific
        #   parameters(under key :data) and information about the device
        #   on which the keypair was created(under key :device and :device_name).
        #   example: {data: {my_key1: "my_val1", my_key2: "my_val2"}, device: "iPhone6s", device_name: "Space grey one"}
        # @return [Card] Created local card that is not published to Virgil Security services
        # @example Create unpublished local card
        #   client = Client::VirgilClient.new()
        #   crypto = Cryptography::VirgilCrypto.new
        #   alice_keys = crypto.generate_keys()
        #   alice_card = client.new_card(
        #       "alice",
        #       "unknown",
        #       alice_keys.private_key,
        #       {data: {}, device: "iPhone6s", device_name: "Space grey one"}
        #   )
        #   # Then you can export created local card and transmit it to the server
        # @see Card#export Export created card
        def new_card(identity, identity_type, private_key, custom_data={})
          data = custom_data[:data]
          custom_data.delete(:data)
          request = Client::Requests::CreateCardRequest.new(
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
        # @param identity [String] Created card identity.
        # @param identity_type [String] Created card identity type.
        # @param private_key [Cryptography::Keys::PrivateKey] Private key of the created card.
        # @param custom_data [Hash] contains application specific
        #   parameters(under key :data) and information about the device
        #   on which the keypair was created(under key :device and :device_name).
        #   example: {data: {my_key1: "my_val1", my_key2: "my_val2"}, device: "iPhone6s", device_name: "Space grey one"}
        # @return [Card] Created global card that is not published to Virgil Security services
        def new_global_card(identity, identity_type, private_key, custom_data={})
          data = custom_data[:data]
          custom_data.delete(:data)
          request = Client::Requests::CreateCardRequest.new(
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


        # Signs and publishes card in Virgil cards service.
        # @param card [Card] created card.
        # @param app_id [String] Application identity for authority sign.
        # @param app_key [Cryptography::Keys::PrivateKey] Application key for authority sign.
        # @return [Card] Card that is published to Virgil Security services
        # @example Sign and publish local card
        #
        #   client.sign_and_publish_card(alice_card, app_id, app_key)
        def sign_and_publish_card(card, app_id, app_key)
          request = card.to_request
          request_signer.authority_sign(
              request,
              app_id,
              app_key
          )
          create_card_from_signed_request(request)
        end


        # Publishes Global card in Virgil cards service.
        # @param card [Card] Created Global card.
        # @return [Card] Global card that is published to Virgil Security services
        def publish_as_global_card(card)
          request = card.to_request
          create_card_from_signed_request(request)
        end


        # Create new published card from signed creation request.
        # @param create_request [Requests::CreateCardRequest] signed card creation request.
        # @return [Card] Created card from server response.
        # @raise [VirgilClient.InvalidCardException] if client has validator
        #   and returned card signatures are not valid.
        # @example create published card through [Requests::CreateCardRequest]
        #   exported_public_key = crypto.export_public_key(alice_keys.public_key)
        #   create_card_request = Client::Requests::CreateCardRequest.new(
        #       identity: "alice",
        #       identity_type: "unknown",
        #       public_key: exported_public_key
        #   )
        #   request_signer = Client::RequestSigner.new(crypto)
        #
        #   request_signer.self_sign(create_card_request, alice_keys.private_key)
        #   request_signer.authority_sign(create_card_request, app_id, app_key)
        #
        #   alice_card = client.create_card_from_signed_request(create_card_request)
        # @see RequestSigner#authority_sign Sign passed request with authority private key.
        # @see RequestSigner#self_sign Sign passed request with private key.
        def create_card_from_signed_request(create_request)
          http_request = Client::HTTP::Request.new(
              method: Client::HTTP::Request::POST,
              endpoint: "/#{Card::VRA_VERSION}/card",
              body: create_request.request_model
          )
          raw_response = self.ra_connection.send_request(http_request)
          card = Card.from_response(raw_response)
          self.validate_cards([card]) if self.card_validator
          card
        end


        # Adds a relation for the Virgil Card to Virgil cards service.
        # @param request [AddRelationRequest] request that contains a trusted card.
        #   Updated card from server response. It's an instance of Card class.
        # @raise [ArgumentError] if request doesn't have trusted card's snapshot or doesn't have exactly 1 signature.
        # @raise [Client::HTTP::BaseConnection::ApiError] if some error has occurred on the server.
        # @return [Card]  Updated card from server response.
        # @example Add bob_card as a relation to alice_card
        #   alice_card = client.create_card(
        #       "alice",
        #       "unknown",
        #       alice_keys,
        #       app_id,
        #       app_key
        #   )
        #   bob_card = client.create_card(
        #       "bob",
        #       "unknown",
        #       bob_keys,
        #       app_id,
        #       app_key
        #   )
        #
        #   add_relation_request = Client::Requests::AddRelationRequest.new(
        #       bob_card
        #   )
        #   request_signer = Client::RequestSigner.new(crypto)
        #   request_signer.authority_sign(add_relation_request, alice_card.id, alice_keys.private_key)
        #   updated_alice_card = client.add_relation(add_relation_request)
        # @see #create_card Create published card
        def add_relation(request)
          unless (request.is_a?(Requests::AddRelationRequest) && !request.snapshot.nil? && request.signatures.count == 1)
            raise ArgumentError.new("Request is not valid. Request must have snapshot and exactly 1 relation signature.")
          end
          http_request = Client::HTTP::Request.new(
              method: Client::HTTP::Request::POST,
              endpoint: "/#{Card::VC_VERSION}/card/#{request.signatures.keys.first}/collections/relations",
              body: request.request_model
          )
          raw_response = self.cards_connection.send_request(http_request)
          card = Card.from_response(raw_response)
          self.validate_cards([card]) if self.card_validator
          card
        end


        # Deletes a relation for the Virgil Card to Virgil cards service.
        # @param request [DeleteRelationRequest] request that contains a trusted card to be deleted.
        # @return [Card] Updated card from server response.
        # @raise [ArgumentError] if request doesn't have trusted card's snapshot or doesn't have exactly 1 signature.
        # @raise [Client::HTTP::BaseConnection::ApiError] if some error has occurred on the server.
        # @example delete bob_card from alice_card's relations
        #   delete_relation_request = Client::Requests::DeleteRelationRequest.new({card_id: bob_card.id})
        #   request_signer = Client::RequestSigner.new(crypto)
        #   request_signer.authority_sign(delete_relation_request, alice_card.id, alice_keys.private_key)
        #
        #   updated_alice_card = client.delete_relation(delete_relation_request)
        # @see #create_card Create published card
        # @see #add_relation Add card as a relation to another card
        def delete_relation(request)
          unless (request.is_a?(Requests::DeleteRelationRequest) && !request.snapshot.nil? && request.signatures.count == 1)
            raise ArgumentError.new("Request is not valid. Request must have snapshot and exactly 1 relation signature.")
          end
          http_request = Client::HTTP::Request.new(
              method: Client::HTTP::Request::DELETE,
              endpoint: "/#{Card::VC_VERSION}/card/#{request.signatures.keys.first}/collections/relations",
              body: request.request_model
          )
          raw_response = self.cards_connection.send_request(http_request)
          card = Card.from_response(raw_response)
          self.validate_cards([card]) if self.card_validator
          card
        end


        # Revoke card by id.
        # @param card_id [String] the id of the revoked card.
        # @param reason [String] card revocation reason.
        #   The possible values can be found in RevokeCardRequest::Reasons class.
        # @param app_id [String] Application identity for authority sign.
        # @param app_key [Cryptography::Keys::PrivateKey] Application key for authority sign.
        # @return [void]
        # @example Revoke published card
        #   client = Client::VirgilClient.new("[YOUR_ACCESS_TOKEN_HERE]")
        #   crypto = Cryptography::VirgilCrypto.new
        #   app_key_password = "[YOUR_APP_KEY_PASSWORD_HERE]"
        #   app_id = "[YOUR_APP_ID_HERE]"
        #   app_key_data = Virgil::Crypto::Bytes.from_string(File.read("[YOUR_APP_KEY_PATH_HERE]"))
        #   app_key = crypto.import_private_key(app_key_data, app_key_password)
        #
        #   client.revoke_card("[SOME_LOCAL_CARD_ID]", app_id, app_key)
        # @see #create_card Create published card
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


        # Revoke Global card by id.
        # @param card_id [String] id of the revoked Global card.
        # @param reason [String] Global card revocation reason.
        #   The possible values can be found in RevokeCardRequest::Reasons class.
        # @param key_pair [Cryptography::Keys::KeyPair]  The Key associated with the revoking Global Card.
        # @param validation_token [HighLevel::VirgilIdentity::ValidationToken] an identity token.
        # @return [void]
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
        # @param revocation_request [Requests::RevokeCardRequest] signed card revocation request.
        # @return [void]
        # @example Revoke card using signed revocation request.
        #   client = Client::VirgilClient.new("[YOUR_ACCESS_TOKEN_HERE]")
        #   crypto = Cryptography::VirgilCrypto.new
        #   request_signer = Client::RequestSigner.new(crypto)
        #   app_id = "[YOUR_APP_ID_HERE]"
        #   app_key_password = "[YOUR_APP_KEY_PASSWORD_HERE]"
        #   app_key_path = "[YOUR_APP_KEY_PATH_HERE]"
        #   app_key_data = Virgil::Crypto::Bytes.from_string(File.read(app_key_path))
        #   app_key = crypto.import_private_key(app_key_data, app_key_password)
        #   card_id = "[YOUR_CARD_ID_HERE]"
        #   
        #   revoke_request = Client::Requests::RevokeCardRequest(
        #       card_id, Client::Requests::RevokeCardRequest::Reasons::Unspecified
        #   )
        #   request_signer.authority_sign(revoke_request, app_id, app_key)
        #   
        #   client.revoke_card_from_signed_request(revoke_request)
        # @see Requests::RevokeCardRequest
        # @see Cryptography::VirgilCrypto#import_private_key Imports the Private key
        #   from material representation.
        # @see RequestSigner#authority_sign Sign passed request with authority private key.
        def revoke_card_from_signed_request(revocation_request)
          http_request = Client::HTTP::Request.new(
              method: HTTP::Request::DELETE,
              endpoint: "/#{Card::VRA_VERSION}/card/#{revocation_request.card_id}",
              body: revocation_request.request_model
          )
          self.ra_connection.send_request(http_request)
        end


        # Sends the request for identity verification, that's will be processed depending of specified type.
        # @param identity [String] An unique string that represents identity.
        # @param identity_type [String] The type of identity.
        # @return [String] The action identifier that is required for confirmation the identity.
        # @note use method confirm_identity to confirm and get the identity token.
        def verify_identity(identity, identity_type)
          verify_identity_request = Requests::VerifyIdentityRequest.new(identity, identity_type)
          http_request = Client::HTTP::Request.new(
              method: HTTP::Request::POST,
              endpoint: "/#{Card::VRA_VERSION}/verify",
              body: verify_identity_request.request_model
          )
          raw_response = self.identity_service_connection.send_request(http_request)
          raw_response['action_id']
        end


        # Confirms the identity using confirmation code, that has been generated to confirm an identity.
        # @param action_id [String] The action identifier that was obtained on verification step.
        # @param confirmation_code [String] The confirmation code that was received on email box.
        # @param time_to_live [Fixnum] The time to live.
        # @param count_to_live [Fixnum] The count to live.
        # @return [String] an identity validation token value.
        def confirm_identity(action_id, confirmation_code, time_to_live, count_to_live)
          confirm_request = Requests::ConfirmIdentityRequest.new(confirmation_code, action_id, time_to_live, count_to_live)
          http_request = Client::HTTP::Request.new(
              method: HTTP::Request::POST,
              endpoint: "/#{Card::VRA_VERSION}/confirm",
              body: confirm_request.request_model
          )
          raw_response = self.identity_service_connection.send_request(http_request)
          raw_response['validation_token']
        end


        # Get card by id.
        # @param card_id [String] id of the card to get.
        # @return [Card] Found card from server response.
        # @raise [VirgilClient::InvalidCardException] if client has validator
        #   and retrieved card signatures are not valid.
        # @example Get card by id.
        #   client = Client::VirgilClient.new("[YOUR_ACCESS_TOKEN_HERE]")
        #   card = client.get_card("[YOUR_CARD_ID_HERE]")
        def get_card(card_id)
          http_request = Client::HTTP::Request.new(
              method: HTTP::Request::GET,
              endpoint: "/#{Card::VC_VERSION}/card/#{card_id}",
          )
          raw_response = self.read_cards_connection.send_request(http_request)
          card = Card.from_response(raw_response)
          self.validate_cards([card]) if self.card_validator
          card
        end


        # Search cards by specified identities.
        # @param identities [Array<String>] identity values for search.
        # @return [Array<Card>] Found cards from server response.
        # @example
        #   client = Client::VirgilClient.new("[YOUR_ACCESS_TOKEN_HERE]")
        #   cards = client.search_cards_by_identities("alice", "bob")
        # @see SearchCriteria.by_identities Create new search criteria for
        #   searching cards by identities.
        def search_cards_by_identities(*identities)
          return self.search_cards_by_criteria(
              SearchCriteria.by_identities(identities)
          )
        end


        # Search cards by specified app bundle.
        # @param bundle [String] application bundle for search.
        # @return [Array<Card>] Found cards from server response.
        # @raise [VirgilClient.InvalidCardException] if client has validator
        #   and cards are not valid.
        # @example
        #   client = Client::VirgilClient.new("[YOUR_ACCESS_TOKEN_HERE]")
        #   app_bundle_cards = client.seach_cards_by_app_bundle("[APP_BUNDLE]")
        # @see SearchCriteria.by_app_bundle Create new search criteria for searching
        #   cards by application bundle.
        def search_cards_by_app_bundle(bundle)
          return self.search_cards_by_criteria(
              SearchCriteria.by_app_bundle(bundle)
          )
        end


        # Search cards by specified search criteria.
        # @param search_criteria [SearchCriteria] constructed search criteria.
        # @return [Array<Card>] Found cards from server response.
        # @raise [VirgilClient.InvalidCardException] if client has validator
        #   and cards are not valid.
        # @example Search cards by specified search criteria
        #   client = Client::VirgilClient.new("[YOUR_ACCESS_TOKEN_HERE]")
        #   criteria = Client::SearchCriteria.by_identities("alice", "bob")
        #   cards = client.search_cards_by_criteria(criteria)
        # @see SearchCriteria.by_identities Create new search criteria for
        #   searching cards by identities.
        def search_cards_by_criteria(search_criteria)
          body = {identities: search_criteria.identities}
          if search_criteria.identity_type
            body[:identity_type] = search_criteria.identity_type
          end
          if search_criteria.scope == Card::GLOBAL
            body[:scope] = Card::GLOBAL
          end
          http_request = Client::HTTP::Request.new(
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
        # @param cards [Array<Card>] list of cards to validate.
        # @raise [VirgilClient::InvalidCardException] if some cards are not valid.
        # @example Validate cards
        #   crypto = Cryptography::VirgilCrypto.new
        #   validator = Client::CardValidator.new(crypto)
        #   validator.add_default_verifiers
        #   validator.add_verifier("[HERE_VERIFIER_CARD_ID]", "[HERE_VERIFIER_PUBLIC_KEY]")
        #   client.card_validator = validator
        #   cards = client.search_cards_by_identities("alice", "bob")
        # @see CardValidator#add_verifier Add signature verifier.
        # @see CardValidator#add_default_verifiers Add default service verifier to validator.
        def validate_cards(cards)
          invalid_cards = cards.select { |card| !card_validator.is_valid?(card) }
          if invalid_cards.any?
            raise InvalidCardException.new(invalid_cards)
          end
        end


        # Cards service connection used for add and delete relations.
        # @return [HTTP::CardsServiceConnection]
        def cards_connection
          @_cards_connection ||= HTTP::CardsServiceConnection.new(
              self.access_token,
              self.cards_service_url
          )
        end


        # The Virgil Registration Authority service connection used for creating and revoking cards.
        # @return [HTTP::CardsServiceConnection]
        def ra_connection
          @_ra_connection ||= HTTP::CardsServiceConnection.new(
              self.access_token,
              self.ra_service_url
          )
        end


        # Cards service connection used for getting and searching cards.
        # @return [HTTP::CardsServiceConnection]
        def read_cards_connection
          @_read_cards_connection = HTTP::CardsServiceConnection.new(
              self.access_token,
              self.cards_read_only_service_url
          )
        end


        # Virgil Identity service connection used for validation of user's identities like email, application, etc.
        # @return [HTTP::CardsServiceConnection]
        def identity_service_connection
          @identity_service_connection = HTTP::CardsServiceConnection.new(
              nil,
              self.identity_service_url
          )

        end


        # Request signer for signing constructed requests.
        # @return [RequestSigner]
        def request_signer
          @_request_signer ||= RequestSigner.new(self.crypto)
        end


        # Crypto library wrapper.
        # @return [Cryptography::VirgilCrypto]
        def crypto
          @_crypto ||= Cryptography::VirgilCrypto.new
        end
      end
    end
  end
end
