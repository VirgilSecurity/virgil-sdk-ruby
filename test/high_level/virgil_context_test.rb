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

class VirgilContextTest < Minitest::Test
  include Virgil::SDK::HighLevel

  def setup
    @keydata = VirgilBuffer.from_string(ClientTestConfig.raw_app_private_key)
    @credentials = VirgilAppCredentials.new(app_id: ClientTestConfig.app_id,
                                            app_key_data: @keydata,
                                            app_key_password: ClientTestConfig.app_key_password)
    @card_verifier_info = VirgilCardVerifierInfo.new(card_verifier_data["card_id"],
                                                     VirgilBuffer.from_base64(card_verifier_data["public_key_value_base64"]))
    @context = VirgilContext.new(
        access_token: ClientTestConfig.access_token,
        credentials: @credentials,
        cards_service_url: ClientTestConfig.card_service_url,
        cards_read_only_service_url: ClientTestConfig.cards_read_only_service_url,
        identity_service_url: ClientTestConfig.identity_service_url,
        card_verifiers: [@card_verifier_info]
    )
  end


  def test_exception_not_the_same_access_token
    assert_raises(Exception) { VirgilApi.new(access_token: "some_access_token", context: @context) }
  end


  def test_default_keystorage_is_created
    assert @context.key_storage
  end


  def test_default_keystorage_folder_is_created
    assert Dir.exist?(@context.key_storage.folder_path)
  end


  def test_client_has_card_validator
    assert @context.client.card_validator
  end


  def test_client_card_validator_gets_additional_card_verifier
    assert_equal @context.client.card_validator.verifiers.count, 2
  end


  def test_exception_with_missing_key_storage_path
    assert_raises(Exception) {
      VirgilContext.new(
          access_token: ClientTestConfig.access_token,
          key_storage_path: "non_existent_folder_path"
      )
    }
  end


  def test_exception_with_unwritable_key_storage_folder
    key_storage_folder_path = "#{tmp_path}/unwritable_key_storage_folder"
    FileUtils.mkdir_p(key_storage_folder_path)
    File.chmod(0400, key_storage_folder_path)
    assert_raises(Exception) {
      VirgilContext.new(
          access_token: ClientTestConfig.access_token,
          key_storage_path: key_storage_folder_path
      )
    }
    File.chmod(0777, key_storage_folder_path)
    FileUtils.rm_rf(key_storage_folder_path)
  end


  def test_exception_with_unreadable_key_storage_folder
    key_storage_folder_path = "#{tmp_path}/unreadable_key_storage_folder"
    FileUtils.mkdir_p(key_storage_folder_path)
    File.chmod(0200, key_storage_folder_path)
    assert_raises(Exception) {
      VirgilContext.new(
          access_token: ClientTestConfig.access_token,
          key_storage_path: key_storage_folder_path
      )
    }
    File.chmod(0777, key_storage_folder_path)
    FileUtils.rm_rf(key_storage_folder_path)
  end


  def card_verifier_data
    @card_verifier_data ||= TestData.card_verifier_data
  end


  def tmp_path
    path = "tmp"
    FileUtils.mkdir(path) unless Dir.exist?(path)
    @tmp_path = path
  end
end