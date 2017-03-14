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

class CardValidatorTest < Minitest::Test
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
    validator = Virgil::SDK::Client::CardValidator.new(@crypto)
    validator.add_default_verifiers
    @client.card_validator = validator
  end

  def test_validate_empty_card_by_default_verifier
    card = Virgil::SDK::Client::Card.new({})
    assert_raises(Exception) { @client.validate_cards([card]) }
  end

  def test_validate_global_card_v3_by_default_verifier
    card = Virgil::SDK::Client::Card.new({})
    card.scope = Virgil::SDK::Client::Card::GLOBAL
    card.version = '3.0'
    assert_nil @client.validate_cards([card])
  end

  def test_validate_with_empty_signatures_by_default_verifier
    alice_keys = @crypto.generate_keys
    alice_card = @client.create_card(
        "alice_card",
        "unknown",
        alice_keys,
        ClientTestConfig.app_id,
        @app_private_key
    )
    @client.validate_cards([alice_card])
    alice_card.signatures = {}
    assert_raises(Exception) { @client.validate_cards([alice_card]) }
    cleanup_cards(alice_card)
  end

  def test_validate_with_empty_snapshot_by_default_verifier
    alice_keys = @crypto.generate_keys
    alice_card = @client.create_card(
        "alice_card",
        "unknown",
        alice_keys,
        ClientTestConfig.app_id,
        @app_private_key
    )
    @client.validate_cards([alice_card])
    alice_card.snapshot = {}
    assert_raises(Exception) { @client.validate_cards([alice_card]) }
    cleanup_cards(alice_card)
  end

  def test_validate_with_wrong_id_by_default_verifier
    alice_keys = @crypto.generate_keys
    alice_card = @client.new_card(
        "alice_card",
        "unknown",
        alice_keys.private_key
    )
    assert_raises(Exception) { @client.validate_cards([alice_card]) }
  end

  def test_validate_global_with_wrong_id_by_default_verifier
    alice_keys = @crypto.generate_keys
    alice_card = @client.new_global_card(
        "name@virgilsecurity.com",
        "email",
        alice_keys.private_key
    )
    assert_raises(Exception) { @client.validate_cards([alice_card]) }
  end


  def test_validate_by_added_verifier
    alice_keys = @crypto.generate_keys
    public_key_bytes = Virgil::Crypto::Bytes.from_base64(ENV['VIRGIL_SERVICE_PUBLIC_KEY_DER_BASE64'])
    public_key = @crypto.import_public_key(public_key_bytes)
    @client.card_validator.add_verifier(ENV['VIRGIL_SERVICE_CARD_ID'], public_key)

    alice_card = @client.create_card(
        "alice_card",
        "unknown",
        alice_keys,
        ClientTestConfig.app_id,
        @app_private_key
    )

    assert_nil @client.validate_cards([alice_card])
    cleanup_cards(alice_card)
  end

  def test_validate_without_self_sing_by_default_verifier
    alice_keys = @crypto.generate_keys
    alice_card = @client.create_card(
        "alice_card",
        "unknown",
        alice_keys,
        ClientTestConfig.app_id,
        @app_private_key
    )
    fingerprint = @crypto.calculate_fingerprint(
        Virgil::Crypto::Bytes.from_string(alice_card.snapshot)
    )
    fingerprint_hex = fingerprint.to_hex

    alice_card.signatures.delete(fingerprint_hex)
    assert_raises(Exception) { @client.validate_cards([alice_card]) }
  end

  def test_validate_with_wrong_self_sing_by_default_verifier
    alice_keys = @crypto.generate_keys
    alice_card = @client.create_card(
        "alice_card",
        "unknown",
        alice_keys,
        ClientTestConfig.app_id,
        @app_private_key
    )
    fingerprint = @crypto.calculate_fingerprint(
        Virgil::Crypto::Bytes.from_string(alice_card.snapshot)
    )
    fingerprint_hex = fingerprint.to_hex

    # card must be valid if add self sign with card's key
    alice_card.signatures[fingerprint_hex] = Base64.strict_encode64(@crypto.sign(
        fingerprint.value,
        alice_keys.private_key
    ).to_s)

    assert_nil @client.validate_cards([alice_card])

    # card must be invalid if add self sign with another key
    alice_card.signatures[fingerprint_hex] = Base64.strict_encode64(@crypto.sign(
        fingerprint.value,
        @crypto.generate_keys.private_key
    ).to_s)
    assert_raises(Exception) { @client.validate_cards([alice_card]) }
    cleanup_cards(alice_card)
  end

  def test_validate_with_wrong_authority_sing_by_default_verifier
    @client.card_validator.add_verifier(ClientTestConfig.app_id,
                                        @crypto.extract_public_key(@app_private_key))
    alice_keys = @crypto.generate_keys
    alice_card = @client.create_card(
        "alice_card",
        "unknown",
        alice_keys,
        ClientTestConfig.app_id,
        @app_private_key
    )
    fingerprint = @crypto.calculate_fingerprint(
        Virgil::Crypto::Bytes.from_string(alice_card.snapshot)
    )

    # card must be valid if add self sign with card's key
    alice_card.signatures[ClientTestConfig.app_id] = Base64.strict_encode64(@crypto.sign(
        fingerprint.value,
        @app_private_key
    ).to_s)

    assert_nil @client.validate_cards([alice_card])

    # card must be invalid if add self sign with another key
    alice_card.signatures[ClientTestConfig.app_id] = Base64.strict_encode64(@crypto.sign(
        fingerprint.value,
        @crypto.generate_keys.private_key
    ).to_s)
    assert_raises(Exception) { @client.validate_cards([alice_card]) }
    cleanup_cards(alice_card)
  end

  def cleanup_cards(*cards)
    cards.each do |card|
      @client.revoke_card(card.id, ClientTestConfig.app_id, @app_private_key)
    end
  end


end

