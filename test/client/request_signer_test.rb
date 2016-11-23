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

class RequestSignerTest < Minitest::Test
  def setup
    @crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
    @app_private_key = @crypto.import_private_key(
      Virgil::SDK::Bytes.from_string(ClientTestConfig.raw_app_private_key),
      ClientTestConfig.app_key_password
    )
    @request_signer = Virgil::SDK::Client::RequestSigner.new(@crypto)
  end

  def test_authority_sign_create_card_request
    alice_keys = @crypto.generate_keys
    request = Virgil::SDK::Client::Requests::CreateCardRequest.new(
      identity: "alice",
      identity_type: "username",
      raw_public_key: alice_keys.public_key.value
    )
    @request_signer.authority_sign(
      request,
      ClientTestConfig.app_id,
      @app_private_key
    )
    assert_equal(
      request.signatures.count,
      1,
    )
    assert_equal(
      request.signatures.keys[0],
      ClientTestConfig.app_id
    )
    self.assert_verify(
      request.signatures.values[0],
      request.snapshot,
      @crypto.extract_public_key(@app_private_key)
    )
  end

  def test_authority_sign_revoke_card_request
    request = Virgil::SDK::Client::Requests::RevokeCardRequest.new(
      card_id: "some_card_id",
    )
    @request_signer.authority_sign(
      request,
      ClientTestConfig.app_id,
      @app_private_key,
    )
    assert_equal(
      request.signatures.count,
      1,
    )
    assert_equal(
      request.signatures.keys[0],
      ClientTestConfig.app_id
    )
    assert_verify(
      request.signatures.values[0],
      request.snapshot,
      @crypto.extract_public_key(@app_private_key)
    )
  end

  def test_self_sign_create_card_request
    alice_keys = @crypto.generate_keys
    request = Virgil::SDK::Client::Requests::CreateCardRequest.new(
      identity: "alice",
      identity_type: "username",
      raw_public_key: alice_keys.public_key.value,
    )
    @request_signer.self_sign(
      request,
      alice_keys.private_key
    )
    assert_equal(
      request.signatures.count,
      1,
    )
    assert_verify(
      request.signatures.values[0],
      request.snapshot,
      alice_keys.public_key
    )
  end

  def test_self_sign_revoke_card_request
    alice_keys = @crypto.generate_keys
    request = Virgil::SDK::Client::Requests::RevokeCardRequest.new(
      card_id: "some_card_id"
    )
    @request_signer.self_sign(
      request,
      alice_keys.private_key
    )
    assert_equal(
      request.signatures.count,
      1,
    )
    assert_verify(
      request.signatures.values[0],
      request.snapshot,
      alice_keys.public_key
    )
  end

  def test_self_and_authority_sign_create_card_request
    alice_keys = @crypto.generate_keys
    request = Virgil::SDK::Client::Requests::CreateCardRequest.new(
      identity: "alice",
      identity_type: "username",
      raw_public_key: alice_keys.public_key.value,
    )
    @request_signer.self_sign(
      request,
      alice_keys.private_key
    )
    @request_signer.authority_sign(
      request,
      ClientTestConfig.app_id,
      @app_private_key,
    )
    assert_equal(
      request.signatures.count,
      2,
    )
    authority_signature = request.signatures.delete(ClientTestConfig.app_id)
    assert_verify(
      authority_signature,
      request.snapshot,
      @crypto.extract_public_key(@app_private_key)
    )
    assert_verify(
      request.signatures.values[0],
      request.snapshot,
      alice_keys.public_key
    )
  end

  def test_self_and_authority_sign_revoke_card_request
    alice_keys = @crypto.generate_keys
    request = Virgil::SDK::Client::Requests::RevokeCardRequest.new(
      card_id: "some_card_id"
    )
    @request_signer.self_sign(
      request,
      alice_keys.private_key
    )
    @request_signer.authority_sign(
      request,
      ClientTestConfig.app_id,
      @app_private_key,
    )
    assert_equal(
      request.signatures.count,
      2,
    )
    authority_signature = request.signatures.delete(ClientTestConfig.app_id)
    assert_verify(
      authority_signature,
      request.snapshot,
      @crypto.extract_public_key(@app_private_key)
    )
    assert_verify(
      request.signatures.values[0],
      request.snapshot,
      alice_keys.public_key
    )

  end


  def assert_verify(signature, snapshot, public_key)
    fingerprint = @crypto.calculate_fingerprint(
      snapshot
    )
    verified = @crypto.verify(
      fingerprint.value,
      signature,
      public_key
    )
    assert(verified)
  end
end

