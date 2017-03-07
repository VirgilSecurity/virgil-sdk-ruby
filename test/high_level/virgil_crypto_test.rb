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
class VirgilHighLevelCryptoTest< Minitest::Test
  include Virgil::SDK::HighLevel

  def setup
    @api = VirgilApi.new(access_token: ClientTestConfig.access_token)

    @alice_key = @api.keys.generate
    @alice_card = @api.cards.create("alice_card", @alice_key)

    @bob_key = @api.keys.generate
    @bob_card = @api.cards.create("bob_card", @bob_key)

  end


  def test_encrypt_and_decrypt
    str = "Hello Guys, let's get outta here."
    buffer = VirgilBuffer.from_string(str)

    cipher_data_buffer = @alice_card.encrypt(buffer)
    cipher_data_bytes = @alice_card.encrypt(buffer.bytes)
    cipher_data_str = @alice_card.encrypt(str)


    transfer_data = cipher_data_buffer.to_base64
    encrypted_buffer = VirgilBuffer.from_base64(transfer_data)

    decrypt_buffer = @alice_key.decrypt(encrypted_buffer)
    decrypt_bytes = @alice_key.decrypt(encrypted_buffer.bytes)
    decrypt_str = @alice_key.decrypt(transfer_data)

    assert_equal str, decrypt_buffer.to_s
    assert_equal str, decrypt_bytes.to_s
    assert_equal str, decrypt_str.to_s

  end


  def test_sign_and_verify
    message = "Generate signature of message using alice's key pair"
    signature = @alice_key.sign(message)

    assert_equal signature, @alice_key.sign(message.bytes)
    assert_equal signature, @alice_key.sign(VirgilBuffer.from_string(message))
    transfer_signature_data = signature.to_base64

    assert_equal @alice_card.verify(message, transfer_signature_data), true

    signature_data = VirgilBuffer.from_base64(transfer_signature_data)

    assert_equal @alice_card.verify(message, signature_data), true
    assert_equal @alice_card.verify(message, signature.bytes), true

    assert_equal @alice_card.verify(VirgilBuffer.from_string(message), signature_data), true
    assert_equal @alice_card.verify(message.bytes, signature_data), true

  end

  def test_sign_then_encrypt_and_decrypt_then_verify
    message = "We want to sign then encrypt message"
    buffer = VirgilBuffer.from_utf8(message)
    signed_and_encrypted_buffer = @alice_key.sign_then_encrypt(buffer, [@alice_card])
    signed_and_encrypted_str = @alice_key.sign_then_encrypt(message, [@alice_card])
    signed_and_encrypted_bytes = @alice_key.sign_then_encrypt(message.bytes, [@alice_card])

    decrypted_and_verified_buf = @alice_key.decrypt_then_verify(signed_and_encrypted_buffer, @alice_card)
    decrypted_and_verified_str = @alice_key.decrypt_then_verify(signed_and_encrypted_str.to_base64, @alice_card)
    decrypted_and_verified_bytes = @alice_key.decrypt_then_verify(signed_and_encrypted_bytes.bytes, @alice_card)

    assert_equal decrypted_and_verified_buf.to_s, decrypted_and_verified_str.to_s
    assert_equal decrypted_and_verified_bytes.to_s, decrypted_and_verified_str.to_s
  end

end