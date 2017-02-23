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
    @keydata = VirgilBuffer.from_string(ClientTestConfig.raw_app_private_key).bytes
    @credentials = VirgilAppCredentials.new(app_id: ClientTestConfig.app_id,
                                            app_key_data: @keydata,
                                            app_key_password: ClientTestConfig.app_key_password)
    @context = VirgilContext.new(
        access_token: ClientTestConfig.access_token,
        credentials: @credentials,
        cards_service_url: ClientTestConfig.card_service_url,
        cards_read_only_service_url: ClientTestConfig.cards_read_only_service_url,
        identity_service_url: ClientTestConfig.identity_service_url,
        card_verifiers: [@card_verifier_info]
    )
    @api_with_token = VirgilApi.new(access_token: ClientTestConfig.access_token)
    @api_with_context = VirgilApi.new(context: @context)
    @api_with_empty_token = VirgilApi.new()

    @device = "samsung"
    @device_name = "samsung 7"
    @data = {a: "some_val_a", b: "some_val_b"}
    @identity = "test_alice_local_card"
    @alice_key = @api_with_empty_token.keys.generate


    @virgil_card = @api_with_token.cards.create(@identity, @alice_key,
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


  def test_export_import_publish_revoke
    assert_raises(Exception) {@virgil_card.publish}

    exported = @virgil_card.export
    assert exported

    assert_raises(Exception) {@api_with_token.cards.import("sdsfs")}

    imported_card_without_credentials = @api_with_token.cards.import(exported)
    assert_raises(Exception) {imported_card_without_credentials.publish}

    imported_card_with_credentials = @api_with_context.cards.import(exported)
    imported_card_with_credentials.publish

    assert_equal(imported_card_with_credentials.device, @device)
    assert_equal(imported_card_with_credentials.device_name, @device_name)
    assert imported_card_with_credentials.data
    assert_equal(imported_card_with_credentials.identity, @identity)
    assert_equal(imported_card_with_credentials.public_key.value,
                 @alice_key.export_public_key.bytes)
    assert imported_card_with_credentials.id

    # card can't be revoke under Virgil Api which does'nt have application credentials
    assert_raises(Exception) {@api_with_token.cards.revoke(imported_card_with_credentials)}
    @api_with_context.cards.revoke(imported_card_with_credentials)


  end


  def test_find_card

    exported = @virgil_card.export
    imported_card_with_credentials = @api_with_context.cards.import(exported)
    imported_card_with_credentials.publish

    assert_raises(Exception) { @api_with_empty_token.cards.get(imported_card_with_credentials.id)}

    assert_raises(Exception) { @api_with_empty_token.cards.find(@identity)}

    found_cards = @api_with_token.cards.find(@identity, "test_alice_local_card2")
    assert_equal(found_cards.size, 1)
    @api_with_context.cards.revoke(imported_card_with_credentials)

  end

end