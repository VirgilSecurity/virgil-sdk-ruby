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
#   (1) Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
#   (2) Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
#   (3) Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, bytes, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

module Virgil
  module SDK
    module Cryptography
      # Wrapper for cryptographic operations.
      #
      # Class provides a cryptographic operations in applications, such as hashing,
      # signature generation and verification, and encryption and decryption
      class VirgilCrypto
        include Virgil::Crypto

        attr_accessor :key_pair_type

        def initialize(key_pair_type=Keys::KeyPairType::Default)
          @key_pair_type = key_pair_type
        end

        # Exception raised when Signature is not valid
        class SignatureIsNotValid < StandardError
          def to_s
            "Signature is not valid"
          end
        end

        CUSTOM_PARAM_KEY_SIGNATURE = Crypto::Bytes.from_string(
            'VIRGIL-DATA-SIGNATURE'
        )

        CUSTOM_PARAM_KEY_SIGNER_ID = Crypto::Bytes.from_string(
            'VIRGIL-DATA-SIGNER-ID'
        )

        # Generates asymmetric key pair that is comprised of both public and private keys by specified type.
        # @param keys_type [Symbol] type of the generated keys.
        #   The possible values can be found in KeyPairType enum.
        # @return [Keys::KeyPair] Generated key pair.
        # @example
        #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
        #   alice_keys = crypto.generate_keys
        def generate_keys(keys_type=@key_pair_type)
          native_type = Keys::KeyPairType.convert_to_native(keys_type)
          native_key_pair = Crypto::Native::VirgilKeyPair.generate(native_type)
          key_pair_id = self.compute_public_key_hash(native_key_pair.public_key)
          private_key = Keys::PrivateKey.new(
              key_pair_id,
              wrap_bytes(
                  Crypto::Native::VirgilKeyPair.private_key_to_der(
                      native_key_pair.private_key
                  )
              )
          )
          public_key = Keys::PublicKey.new(
              key_pair_id,
              wrap_bytes(
                  Crypto::Native::VirgilKeyPair.public_key_to_der(
                      native_key_pair.public_key
                  )
              )
          )
          return Keys::KeyPair.new(private_key, public_key)
        end

        # Imports the Private key from material representation.
        # @param key_bytes [Crypto::Bytes] private key material representation bytes.
        # @param password [String] private key password, nil by default.
        # @return [Keys::PrivateKey] Imported private key.
        # @example
        #   private_key = crypto.import_private_key(exported_private_key)
        # @see #export_private_key How to get exported_private_key
        def import_private_key(key_bytes, password=nil)
          decrypted_private_key = if !password
                                    Crypto::Native::VirgilKeyPair.private_key_to_der(key_bytes)
                                  else
                                    Crypto::Native::VirgilKeyPair.decrypt_private_key(
                                        key_bytes,
                                        Crypto::Bytes.from_string(password)
                                    )
                                  end

          public_key_bytes = Crypto::Native::VirgilKeyPair.extract_public_key(
              decrypted_private_key, []
          )
          key_pair_id = self.compute_public_key_hash(public_key_bytes)
          private_key_bytes = Crypto::Native::VirgilKeyPair.private_key_to_der(
              decrypted_private_key
          )
          return Keys::PrivateKey.new(key_pair_id, wrap_bytes(private_key_bytes))
        end

        # Imports the Public key from material representation.
        # @param key_bytes [Crypto::Bytes] public key material representation bytes.
        # @return [Keys::PublicKey] Imported public key.
        # @example
        #   public_key = crypto.import_public_key(exported_public_key)
        # @see #export_public_key How to get exported_public_key
        def import_public_key(key_bytes)
          key_pair_id = self.compute_public_key_hash(key_bytes)
          public_key_bytes =
              Crypto::Native::VirgilKeyPair.public_key_to_der(key_bytes)
          Keys::PublicKey.new(key_pair_id, wrap_bytes(public_key_bytes))
        end

        # Exports the Private key into material representation.
        # @param private_key [Keys::PrivateKey] private key for export.
        # @param password [String] private key password, nil by default.
        # @return [Crypto::Bytes] Private key material representation bytes.
        # @example
        #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
        #   alice_keys = crypto.generate_keys
        #   exported_private_key = crypto.export_private_key(alice_keys.private_key)
        def export_private_key(private_key, password=nil)
          unless password
            return Crypto::Native::VirgilKeyPair.private_key_to_der(
                private_key.value
            )
          end

          password_bytes = Crypto::Bytes.from_string(password)
          private_key_bytes = Crypto::Native::VirgilKeyPair.encrypt_private_key(
              private_key.value,
              password_bytes
          )
          wrap_bytes(
              Crypto::Native::VirgilKeyPair.private_key_to_der(
                  private_key_bytes,
                  password_bytes
              )
          )
        end

        # Exports the Public key into material representation.
        # @param public_key [Keys::PublicKey] public key for export.
        # @return [Crypto::Bytes] Key material representation bytes.
        # @example
        #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
        #   alice_keys = crypto.generate_keys
        #   exported_private_key = crypto.export_private_key(alice_keys.private_key)
        def export_public_key(public_key)
          wrap_bytes(
              Crypto::Native::VirgilKeyPair.public_key_to_der(public_key.value)
          )
        end

        # Extracts the Public key from Private key.
        # @param private_key [Keys::PrivateKey] source private key for extraction.
        # @return  [Keys::PublicKey] Exported public key.
        def extract_public_key(private_key)
          public_key_bytes = Crypto::Native::VirgilKeyPair.extract_public_key(
              private_key.value,
              []
          )
          Keys::PublicKey.new(
              private_key.receiver_id,
              wrap_bytes(
                  Crypto::Native::VirgilKeyPair.public_key_to_der(public_key_bytes)
              )
          )
        end

        # Encrypts the specified bytes using recipients Public keys.
        # @param bytes [Virgil::Crypto::Bytes] raw data bytes for encryption.
        # @param *recipients [Array<Keys::PublicKey>] list of recipients' public keys.
        # @return [Crypto::Bytes] Encrypted bytes.
        # @example
        #   # Data encryption using ECIES scheme with AES-GCM.
        #   # There can be more than one recipient.
        #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
        #   alice_keys = crypto.generate_keys
        #   plain_data = Virgil::Crypto::Bytes.from_string("Hello Bob!")
        #   cipher_data = crypto.encrypt(plain_data, alice_keys.public_key)
        # @see #generate_keys
        def encrypt(bytes, *recipients)
          cipher = Crypto::Native::VirgilCipher.new
          recipients.each do |public_key|
            cipher.add_key_recipient(public_key.receiver_id, public_key.value)
          end
          wrap_bytes(cipher.encrypt(bytes))
        end

        # Decrypts the specified bytes using Private key.
        # @param cipher_bytes [Crypto::Bytes] encrypted bytes bytes for decryption.
        # @param private_key [Keys::PrivateKey] private key for decryption.
        # @return [Crypto::Bytes] Decrypted bytes bytes.
        # @example
        #   # You can decrypt data using your private key
        #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
        #   alice_keys = crypto.generate_keys
        #   plain_data = crypto.decrypt(cipher_data, alice_keys.private_key)
        # @see #generate_keys
        # @see #encrypt How to get cipher_data
        def decrypt(cipher_bytes, private_key)
          cipher = Crypto::Native::VirgilCipher.new
          decrypted_bytes = cipher.decrypt_with_key(
              cipher_bytes,
              private_key.receiver_id,
              private_key.value
          )
          wrap_bytes(decrypted_bytes)
        end

        # Signs and encrypts the data.
        # @param bytes [Crypto::Bytes] data bytes for signing and encryption.
        # @param private_key [Keys::PrivateKey] private key to sign the data.
        # @param *recipients [Array<Keys::PublicKey>] list of recipients' public keys
        #   used for data encryption.
        # @return [Crypto::Bytes] Signed and encrypted data bytes.
        def sign_then_encrypt(bytes, private_key, *recipients)
          signer = Crypto::Native::VirgilSigner.new
          signature = signer.sign(bytes, private_key.value)
          cipher = Crypto::Native::VirgilCipher.new
          custom_bytes = cipher.custom_params
          custom_bytes.set_data(
              CUSTOM_PARAM_KEY_SIGNATURE,
              signature
          )

          public_key = extract_public_key(private_key)
          custom_bytes.set_data(
              CUSTOM_PARAM_KEY_SIGNER_ID,
              wrap_bytes(public_key.receiver_id)
          )

          recipients.each do |public_key|
            cipher.add_key_recipient(public_key.receiver_id, public_key.value)
          end
          wrap_bytes(cipher.encrypt(bytes))
        end

        # Decrypts and verifies the data.
        # @param bytes [Crypto::Bytes] encrypted data bytes.
        # @param private_key [Keys::PrivateKey] private key for decryption.
        # @param *public_keys [Array<Keys::PublicKey>] a list of public keys for verification,
        #   which can contain signer's public key.
        # @return [Crypto::Bytes] Decrypted data bytes.
        # @raise [SignatureIsNotValid] if signature is not verified.
        def decrypt_then_verify(bytes, private_key, *public_keys)
          cipher = Crypto::Native::VirgilCipher.new
          decrypted_bytes = cipher.decrypt_with_key(
              bytes,
              private_key.receiver_id,
              private_key.value
          )
          signature = cipher.custom_params.get_data(CUSTOM_PARAM_KEY_SIGNATURE)

          signer_public_key = public_keys.first
          if public_keys.count > 1
            signer_id = cipher.custom_params.get_data(CUSTOM_PARAM_KEY_SIGNER_ID)
            signer_public_key = public_keys.find{|public_key| public_key.receiver_id == signer_id}
          end

          is_valid = self.verify(decrypted_bytes, signature, signer_public_key)
          unless is_valid
            raise SignatureIsNotValid.new
          end
          wrap_bytes(decrypted_bytes)
        end


        # Signs the specified data using Private key.
        # @param bytes [Crypto::Bytes] raw data bytes for signing.
        # @param private_key [Keys::PrivateKey] private key for signing.
        # @return [Crypto::Bytes] Signature data.
        # @example Sign the SHA-384 fingerprint of bytes using your private key.
        #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
        #   alice_keys = crypto.generate_keys()
        #   # The data to be signed with alice's Private key
        #   data = Virgil::Crypto::Bytes.from_string("Hello Bob, How are you?")
        #   signature = crypto.sign(data, alice.private_key)
        # @see #generate_keys
        def sign(bytes, private_key)
          signer = Crypto::Native::VirgilSigner.new
          wrap_bytes(signer.sign(bytes, private_key.value))
        end


        # Verifies the specified signature using original data and signer's public key.
        # @param bytes [Crypto::Bytes] original data bytes for verification.
        # @param signature [Crypto::Bytes] signature bytes for verification.
        # @param signer_public_key [Keys::PublicKey] signer public key for verification.
        # @return [Boolean] True if signature is valid, False otherwise.
        # @example Verify the signature of the SHA-384 fingerprint of bytes using Public key.
        #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
        #   alice_keys = crypto.generate_keys()
        #   data = Virgil::Crypto::Bytes.from_string("Hello Bob, How are you?")
        #   is_valid = crypto.verify(data, signature, alice.public_key)
        # @see #sign How to get signature
        def verify(bytes, signature, signer_public_key)
          signer = Crypto::Native::VirgilSigner.new
          signer.verify(bytes, signature, signer_public_key.value)
        end

        # Encrypts the specified stream using recipients Public keys.
        # @param input_stream [StringIO] readable stream containing input bytes.
        # @param output_stream [StringIO] writable stream for output.
        # @param *recipients [Array<Keys::PublicKey>] list of recipients' public keys.
        # @return [Crypto::Bytes] encrypted bytes.
        def encrypt_stream(input_stream, output_stream, *recipients)
          cipher = Crypto::Native::VirgilChunkCipher.new
          recipients.each do |public_key|
            cipher.add_key_recipient(public_key.receiver_id, public_key.value)
          end
          source = Crypto::VirgilStreamDataSource.new(input_stream)
          sink = Crypto::VirgilStreamDataSink.new(output_stream)
          wrap_bytes(cipher.encrypt(source, sink))
        end

        # Decrypts the specified stream using Private key.
        # @param input_stream [StringIO] readable stream containing input data.
        # @param output_stream [StringIO] writable stream for output.
        # @param private_key [Keys::PrivateKey] private key for decryption.
        # @return [Crypto::Bytes] Decrypted data bytes.
        def decrypt_stream(input_stream, output_stream, private_key)
          cipher = Crypto::Native::VirgilChunkCipher.new
          source = Crypto::VirgilStreamDataSource.new(input_stream)
          sink = Crypto::VirgilStreamDataSink.new(output_stream)
          cipher.decrypt_with_key(
              source,
              sink,
              private_key.receiver_id,
              private_key.value
          )
        end

        # Signs the specified stream using Private key.
        # @param input_stream [StringIO] readable stream containing input data.
        # @param private_key [Keys::PrivateKey] private key for signing.
        # @return [Crypto::Bytes] Signature bytes.
        def sign_stream(input_stream, private_key)
          signer = Crypto::Native::VirgilStreamSigner.new
          source = Crypto::VirgilStreamDataSource.new(input_stream)
          wrap_bytes(signer.sign(source, private_key.value))
        end

        # Verifies the specified signature using original stream and signer's Public key.
        # @param input_stream [StringIO] readable stream containing input data.
        # @param signature [Crypto::Bytes] signature bytes for verification.
        # @param signer_public_key [Keys::PublicKey] signer public key for verification.
        # @return [Boolean] True if signature is valid, False otherwise.
        def verify_stream(input_stream, signature, signer_public_key)
          signer = Crypto::Native::VirgilStreamSigner.new
          source = Crypto::VirgilStreamDataSource.new(input_stream)
          signer.verify(source, signature, signer_public_key.value)
        end

        # Calculates the fingerprint.
        # @param bytes [Crypto::Bytes] data bytes for fingerprint calculation.
        # @return [Hashes::Fingerprint] Fingerprint of the source data.
        def calculate_fingerprint(bytes)
          hash_bytes = self.compute_hash(bytes, Hashes::HashAlgorithm::SHA256)
          Hashes::Fingerprint.new(hash_bytes)
        end

        # Computes the hash of specified data.
        # @param bytes [Crypto::Bytes] data bytes for fingerprint calculation.
        # @param algorithm [Hashes::HashAlgorithm] hashing algorithm.
        #   The possible values can be found in HashAlgorithm enum.
        # @return [Crypto::Bytes] Hash bytes.
        def compute_hash(bytes, algorithm)
          native_algorithm = Hashes::HashAlgorithm.convert_to_native(algorithm)
          native_hasher = Crypto::Native::VirgilHash.new(native_algorithm)
          wrap_bytes(native_hasher.hash(bytes))
        end

        # Computes the hash of specified public key using SHA256 algorithm.
        # @param public_key [Keys::PublicKey] public key for hashing.
        # @return [Crypto::Bytes] Hash bytes.
        def compute_public_key_hash(public_key)
          public_key_der = Crypto::Native::VirgilKeyPair.public_key_to_der(public_key)
          self.compute_hash(public_key_der, Hashes::HashAlgorithm::SHA256)
        end

        private

        def wrap_bytes(raw_bytes)
          Crypto::Bytes.new(raw_bytes)
        end
      end
    end
  end
end
