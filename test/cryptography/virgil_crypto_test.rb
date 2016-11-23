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

class VirgilCryptoTest < Minitest::Test
  def setup
    @crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
  end

  def test_import_private_key
    key_pair = @crypto.generate_keys()
    private_key_data = key_pair.private_key.value
    assert_equal(
      @crypto.import_private_key(private_key_data),
      key_pair.private_key
    )
  end

  def test_import_public_key
    key_pair = @crypto.generate_keys()
    public_key_data = key_pair.public_key.value
    assert_equal(
      @crypto.import_public_key(public_key_data),
      key_pair.public_key
    )
  end

  def test_export_and_import_private_key_with_password
    password = '123456'
    key_pair = @crypto.generate_keys()
    exported_private_key = @crypto.export_private_key(
      key_pair.private_key,
      password
    )
    refute_equal(
      exported_private_key,
      key_pair.private_key.value
    )
    imported_private_key = @crypto.import_private_key(
      exported_private_key,
      password
    )
    assert_equal(
      imported_private_key,
      key_pair.private_key
    )
  end

  def test_export_public_key
    key_pair = @crypto.generate_keys()
    exported_public_key = @crypto.export_public_key(
      key_pair.public_key
    )
    assert_equal(
      exported_public_key,
      key_pair.public_key.value
    )
  end

  def test_extract_public_key
    key_pair = @crypto.generate_keys()
    extracted_public_key = @crypto.extract_public_key(
      key_pair.private_key,
    )
    assert_equal(
      extracted_public_key,
      key_pair.public_key
    )
  end

  def test_encrypt_and_decrypt_values
    data = [1, 2, 3]
    key_pair = @crypto.generate_keys()
    encrypt_result = @crypto.encrypt(
      data,
      key_pair.public_key
    )
    decrypt_result = @crypto.decrypt(
      encrypt_result,
      key_pair.private_key
    )
    assert_equal(
      data,
      decrypt_result
    )
  end

  #def test_encrypt_and_decrypt_stream
  #  data = Virgil::SDK::Bytes.new([1, 2, 3])
  #  key_pair = @crypto.generate_keys()
  #  encrypt_input_stream = io.BytesIO(data)
  #  encrypt_output_stream = io.BytesIO()
  #  @crypto.encrypt_stream(
  #    encrypt_input_stream,
  #    encrypt_output_stream,
  #    key_pair.public_key
  #  )
  #  encrypt_stream_result = encrypt_output_stream.getvalue()
  #  decrypt_input_stream = io.BytesIO(encrypt_stream_result)
  #  decrypt_output_stream = io.BytesIO()
  #  @crypto.decrypt_stream(
  #    decrypt_input_stream,
  #    decrypt_output_stream,
  #    key_pair.private_key
  #  )
  #  decrypt_stream_result = decrypt_output_stream.getvalue()
  #  assert_equal(
  #    data,
  #    decrypt_stream_result
  #  )
  #end

  def test_sign_and_verify_values
    data = [1, 2, 3]
    key_pair = @crypto.generate_keys()
    signature = @crypto.sign(
      data,
      key_pair.private_key
    )
    verified = @crypto.verify(
      data,
      signature,
      key_pair.public_key
    )
    assert(verified)
  end

  #def test_sign_and_verify_stream
  #  data = Virgil::SDK::Bytes.new([1, 2, 3])
  #  key_pair = @crypto.generate_keys()
  #  sign_input_stream = io.BytesIO(data)
  #  signature = @crypto.sign_stream(
  #    sign_input_stream,
  #    key_pair.private_key
  #  )
  #  verify_input_stream = io.BytesIO(data)
  #  verified = @crypto.verify_stream(
  #    verify_input_stream,
  #    signature,
  #    key_pair.public_key
  #  )
  #  assert(verified)
  #end

  def test_calculate_fingerprint
    data = Virgil::SDK::Bytes.new([1, 2, 3])
    fingerprint = @crypto.calculate_fingerprint(data)
    assert(fingerprint.value)
    assert(fingerprint.is_a?(Virgil::SDK::Cryptography::Hashes::Fingerprint))
  end
end
