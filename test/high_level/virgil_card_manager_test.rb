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
require "virgil/sdk/high_level"
class VirgilCardManagerTest< Minitest::Test
  include Virgil::SDK::HighLevel

  def setup
    @keydata = VirgilBuffer.from_string(ClientTestConfig.raw_app_private_key)
    @credentials = VirgilAppCredentials.new(app_id: ClientTestConfig.app_id,
                                            app_key_data: @keydata,
                                            app_key_password: ClientTestConfig.app_key_password)
    card_verifier_info = VirgilCardVerifierInfo.new("e680bef87ba75d331b0a02bfa6a20f02eb5c5ba9bc96fc61ca595404b10026f4",
                                                    VirgilBuffer.from_base64("MCowBQYDK2VwAyEA8jJqWY5hm4tvmnM6QXFdFCErRCnoYdhVNjFggffSCoc="))
    @context = VirgilContext.new(
        access_token: ClientTestConfig.access_token,
        credentials: @credentials,
        cards_service_url: ClientTestConfig.card_service_url,
        cards_read_only_service_url: ClientTestConfig.cards_read_only_service_url,
        identity_service_url: ClientTestConfig.identity_service_url,
        ra_service_url: ClientTestConfig.ra_service_url,
        card_verifiers: [card_verifier_info]
    )

    @pure_context = VirgilContext.new(
        access_token: ClientTestConfig.access_token,
        cards_service_url: ClientTestConfig.card_service_url,
        cards_read_only_service_url: ClientTestConfig.cards_read_only_service_url,
        identity_service_url: ClientTestConfig.identity_service_url,
        ra_service_url: ClientTestConfig.ra_service_url
    )
    @api_without_credentials = VirgilApi.new(context: @pure_context)
    @api_with_context = VirgilApi.new(context: @context)
    @api_with_empty_token = VirgilApi.new()

    @device = "samsung"
    @device_name = "samsung 7"
    @data = {a: "some_val_a", b: "some_val_b"}
    @identity = "test_alice_local_card"
    @alice_key = @api_with_empty_token.keys.generate


    @virgil_card = @api_without_credentials.cards.create(@identity, @alice_key,
                                                         {
                                                    device: @device,
                                                    device_name: @device_name,
                                                    data: @data
                                                })
  end


  def test_create_and_export_card
    assert_equal(@virgil_card.device, @device)
    assert_equal(@virgil_card.device_name, @device_name)
    assert @virgil_card.data
    assert_equal(@virgil_card.identity, @identity)
    assert_equal(@virgil_card.public_key.value,
                 @alice_key.export_public_key.bytes)
    assert_nil @virgil_card.id
  end


  def test_export_import_card
    assert_raises(Exception) { @virgil_card.publish }

    exported = @virgil_card.export
    assert exported

    assert_raises(Exception) { @api_without_credentials.cards.import("sdsfs") }

    imported_card_without_credentials = @api_without_credentials.cards.import(exported)

    assert_equal @virgil_card.public_key, imported_card_without_credentials.public_key
    assert_equal(@virgil_card.device, imported_card_without_credentials.device)
    assert_equal(@virgil_card.device_name, imported_card_without_credentials.device_name)
    assert_equal(@virgil_card.identity, imported_card_without_credentials.identity)
    assert_equal(@virgil_card.identity_type,
                 imported_card_without_credentials.identity_type)
    assert_equal(@virgil_card.scope, imported_card_without_credentials.scope)
    assert_nil imported_card_without_credentials.id
    assert_equal(@virgil_card.data, imported_card_without_credentials.data)

  end

  def test_publish_revoke_card
    # card can't be published under Virgil Api which does'nt have application credentials
    assert_raises(Exception) { @virgil_card.publish }

    exported = @virgil_card.export
    imported_card_without_credentials = @api_without_credentials.cards.import(exported)

    assert_raises(Exception) { imported_card_without_credentials.publish }

    imported_card_with_credentials = @api_with_context.cards.import(exported)

    imported_card_with_credentials.publish

    assert_equal(imported_card_with_credentials.device, @device)
    assert_equal(imported_card_with_credentials.device_name, @device_name)

    assert_equal(@virgil_card.data["a"], imported_card_with_credentials.data["a"])
    assert_equal(imported_card_with_credentials.identity, @identity)
    assert_equal(imported_card_with_credentials.public_key.value,
                 @alice_key.export_public_key.bytes)
    assert imported_card_with_credentials.id

    # card can't be revoke under Virgil Api which does'nt have application credentials
    assert_raises(Exception) { @api_without_credentials.cards.revoke(imported_card_with_credentials) }
    @api_with_context.cards.revoke(imported_card_with_credentials)


  end


  def test_get_card
    exported = @virgil_card.export
    imported_card_with_credentials = @api_with_context.cards.import(exported)
    imported_card_with_credentials.publish
    card_id = imported_card_with_credentials.id

    assert @api_without_credentials.cards.get(card_id)
    # can't get card under Virgil Api which does'nt have application access token
    assert_raises(Exception) { @api_with_empty_token.cards.get(card_id) }
    card = @api_with_context.cards.get(card_id)
    assert_equal @virgil_card.public_key, card.public_key
    assert_equal(@virgil_card.device, card.device)
    assert_equal(@virgil_card.device_name, card.device_name)
    assert_equal(@virgil_card.identity, card.identity)
    assert_equal(@virgil_card.identity_type,
                 card.identity_type)
    assert_equal(@virgil_card.scope, card.scope)
    assert_equal(@virgil_card.data, card.data)
  end


  def test_find_card
    exported = @virgil_card.export
    imported_card_with_credentials = @api_with_context.cards.import(exported)
    imported_card_with_credentials.publish

    @api_without_credentials.cards.find(@identity)
    assert_raises(Exception) { @api_with_empty_token.cards.find(@identity) }

    found_cards = @api_without_credentials.cards.find(@identity, "test_alice_local_card2")
    assert(found_cards.size > 0)
    found_cards.each do |card|
      @api_with_context.cards.revoke(card)
    end
  end


end