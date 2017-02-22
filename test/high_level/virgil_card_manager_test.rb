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
    @identity = "test_alice_card"
    @alice_key = @api_with_empty_token.keys.generate


    @virgil_card = @api_with_token.cards.create(@identity, @alice_key,
                                               {
                                                   device: @device,
                                                   device_name: @device_name,
                                                   data: @data
                                               })
  end

  def test_create_global_card


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
    exported = @virgil_card.export
    assert exported

    assert_raises(Exception) {@api_with_token.cards.import("sdsfs")}

    imported_without_credentials_card = @api_with_token.cards.import(exported)
    assert_raises(Exception) {imported_without_credentials_card.publish}

    imported_with_credentials_card = @api_with_context.cards.import(exported)
    imported_with_credentials_card.publish

    assert_equal(imported_with_credentials_card.device, @device)
    assert_equal(imported_with_credentials_card.device_name, @device_name)
    assert imported_with_credentials_card.data
    assert_equal(imported_with_credentials_card.identity, @identity)
    assert_equal(imported_with_credentials_card.public_key.value,
                 @alice_key.export_public_key.bytes)
    assert imported_with_credentials_card.id

    assert_raises(Exception) {@api_with_token.cards.revoke(imported_with_credentials_card)}
    # @api_with_context.api_with_context

  end

  def test_publish_card

  end

  def test_publish_global_card

  end

  def test_find_card

  end

  def test_find_global_card

  end

  def revoke_card

  end

  def revoke_global_card

  end

  def get_card

  end

  def teardown

  end
end