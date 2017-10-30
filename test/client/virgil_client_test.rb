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
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
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
require 'test_helper'

class VirgilClientTest < Minitest::Test
  def setup
    @crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
    @app_private_key = @crypto.import_private_key(
      Virgil::Crypto::Bytes.from_string(ClientTestConfig.raw_app_private_key),
      ClientTestConfig.app_key_password
    )
    @client = Virgil::SDK::Client::VirgilClient.new(
      ClientTestConfig.access_token,
      ClientTestConfig.card_service_url,
      ClientTestConfig.cards_read_only_service_url,
      ClientTestConfig.identity_service_url,
      ClientTestConfig.ra_service_url
    )
    @client.card_validator = Virgil::SDK::Client::CardValidator.new(@crypto)
  end

  def test_create_card_saves_public_key
    alice_keys = @crypto.generate_keys
    card = @client.create_card(
      "alice_card",
      "unknown",
      alice_keys,
      ClientTestConfig.app_id,
      @app_private_key
    )
    assert_equal(
      card.identity,
      "alice_card"
    )
    assert_equal(
      card.identity_type,
      "unknown"
    )
    assert_equal(
      card.version,
      "4.0"
    )
    assert_equal(
      card.public_key,
      alice_keys.public_key.value,
    )
    self.cleanup_cards(card)
  end

  def test_revoke_card_removes_created_card
    alice_keys = @crypto.generate_keys
    card = @client.create_card(
      "alice_card",
      "unknown",
      alice_keys,
      ClientTestConfig.app_id,
      @app_private_key
    )
    @client.revoke_card(
      card.id,
      ClientTestConfig.app_id,
      @app_private_key
    )
  end

  def test_get_card
    alice_keys = @crypto.generate_keys
    created_card = @client.create_card(
      "alice_card",
      "unknown",
      alice_keys,
      ClientTestConfig.app_id,
      @app_private_key
    )
    card = @client.get_card(created_card.id)
    assert_equal(
      card.id,
      created_card.id
    )
    assert_equal(
      card.public_key,
      created_card.public_key
    )
    assert_equal(
      card.identity,
      created_card.identity
    )
    assert_equal(
      card.identity_type,
      created_card.identity_type
    )
    self.cleanup_cards(created_card)
  end

  def test_search_card_by_identity
    alice_keys1 = @crypto.generate_keys
    alice_card1 = @client.create_card(
      "alice_card",
      "unknown",
      alice_keys1,
      ClientTestConfig.app_id,
      @app_private_key
    )

    alice_keys2 = @crypto.generate_keys
    alice_card2 = @client.create_card(
      "alice_card",
      "unknown",
      alice_keys2,
      ClientTestConfig.app_id,
      @app_private_key
    )
    cards = @client.search_cards_by_identities('alice_card')
    assert_includes(cards, alice_card1)
    assert_includes(cards, alice_card2)
    self.cleanup_cards(*cards)
  end

  def test_search_non_existent_cards_by_search_criteria()
    criteria = Virgil::SDK::Client::SearchCriteria.new(["some_non existent_card_identity"],
                                                       "some_non existent_card_identity_type",
                                                       "application")
    cards = @client.search_cards_by_criteria(criteria)
    assert_equal(cards, [])
  end


  def test_search_cards_by_search_criteria()
    alice_keys1 = @crypto.generate_keys
    alice_card1 = @client.create_card(
        "alice_card",
        "unknown",
        alice_keys1,
        ClientTestConfig.app_id,
        @app_private_key
    )
    criteria = Virgil::SDK::Client::SearchCriteria.new(["alice_card"],
                                                       "unknown",
                                                       "application")
    cards = @client.search_cards_by_criteria(criteria)
    assert_includes(cards, alice_card1)
    self.cleanup_cards(*cards)
  end


  def test_add_remove_relations

    alice_keys = @crypto.generate_keys
    alice_card = @client.create_card(
        "alice_card",
        "unknown",
        alice_keys,
        ClientTestConfig.app_id,
        @app_private_key
    )

    bob_keys = @crypto.generate_keys
    bob_card = @client.create_card(
        "bob",
        "unknown",
        bob_keys,
        ClientTestConfig.app_id,
        @app_private_key
    )

    add_relation_request = Virgil::SDK::Client::Requests::AddRelationRequest.new(
        bob_card
    )
    request_signer = Virgil::SDK::Client::RequestSigner.new(@crypto)

    request_signer.authority_sign(add_relation_request, alice_card.id, alice_keys.private_key)

    updated_alice_card = @client.add_relation(add_relation_request)

    assert_equal(updated_alice_card.relations.count, 1)
    assert_equal(updated_alice_card.relations.keys[0], bob_card.id)
    delete_relation_request = Virgil::SDK::Client::Requests::DeleteRelationRequest.new({card_id: bob_card.id})
    request_signer = Virgil::SDK::Client::RequestSigner.new(@crypto)

    request_signer.authority_sign(delete_relation_request, alice_card.id, alice_keys.private_key)
    updated_alice_card = @client.delete_relation(delete_relation_request)
    assert_equal(updated_alice_card.relations.count, 0)
    self.cleanup_cards(alice_card, bob_card)

  end


  def test_search_card_by_multiple_identities
    alice_keys = @crypto.generate_keys
    alice_card = @client.create_card(
      "alice_card",
      "unknown",
      alice_keys,
      ClientTestConfig.app_id,
      @app_private_key
    )

    bob_keys = @crypto.generate_keys
    bob_card = @client.create_card(
      "bob",
      "unknown",
      bob_keys,
      ClientTestConfig.app_id,
      @app_private_key
    )
    cards = @client.search_cards_by_identities('alice_card', 'bob')
    assert_includes(cards, alice_card)
    assert_includes(cards, bob_card)
    self.cleanup_cards(*cards)

  end

  def test_search_card_by_app_bundle
    cards = @client.search_cards_by_app_bundle(ClientTestConfig.app_bundle)
    assert_equal(
      ClientTestConfig.app_bundle,
      cards[0].identity
    )
  end

  def cleanup_cards(*cards)
    cards.each do |card|
      @client.revoke_card(card.id, ClientTestConfig.app_id, @app_private_key)
    end
  end


end

