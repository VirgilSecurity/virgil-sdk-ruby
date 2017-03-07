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

class VirgilKeyManagerTest < Minitest::Test
  include Virgil::SDK::HighLevel

  def setup
    @virgil = VirgilApi.new()
    @alice_key_name = "test_alice_key123"
    @alice_key_password = "123456"
  end


  def test_generate_and_load_key
    @virgil.keys.generate.save(@alice_key_name, @alice_key_password)
    assert @virgil.keys.load(@alice_key_name, @alice_key_password)
    self.cleanup_keys(@alice_key_name)
  end


  def test_dont_load_key_with_wrong_password
    @virgil.keys.generate.save(@alice_key_name, @alice_key_password)
    assert_raises(Exception) { @virgil.keys.load(@alice_key_name, "1212") }
    self.cleanup_keys(@alice_key_name)
  end


  def test_dont_save_key_with_unique_name
    @virgil.keys.generate.save(@alice_key_name, @alice_key_password)
    assert_raises(Exception) { @virgil.keys.generate.save(@alice_key_name, "") }
    self.cleanup_keys(@alice_key_name)
  end


  def test_load_key_which_was_not_generated
    assert_raises(Exception) { @virgil.keys.load(@alice_key_name) }
  end


  def test_delete_key_which_was_not_generated
    assert_raises(Exception) { @virgil.keys.delete(@alice_key_name) }
  end

  def test_export_and_import

    alice_key = @virgil.keys.generate
    exported_key = alice_key.export("12345678").to_base64
    key_buffer = VirgilBuffer.from_base64(exported_key)
    alice_key_imported = @virgil.keys.import(key_buffer, "12345678")
    assert_equal alice_key.private_key.value.to_base64, alice_key_imported.private_key.value.to_base64

  end

  def cleanup_keys(*key_names)
    key_names.each do |key_name|
      @virgil.keys.delete(key_name)
    end
  end

end