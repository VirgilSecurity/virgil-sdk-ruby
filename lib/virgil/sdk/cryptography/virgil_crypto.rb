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

        # Exception raised when Signature is not valid
        class SignatureIsNotValid < StandardError
          def to_s
             "Signature is not valid"
          end
        end

        CUSTOM_PARAM_KEY_SIGNATURE = Bytes.from_string('VIRGIL-DATA-SIGNATURE')

        # Generates asymmetric key pair that is comprised of both public and private keys by specified type.
        # Args:
        #   key_pair_type: type of the generated keys.
        #     The possible values can be found in KeyPairType enum.
        # Returns:
        #   Generated key pair.
        def generate_keys(key_pair_type=Keys::KeyPairType::Default)
          native_type = Keys::KeyPairType.convert_to_native(key_pair_type)
          native_key_pair = VirgilKeyPair.generate(native_type)
          key_pair_id = self.compute_public_key_hash(native_key_pair.publicKey)
          private_key = Keys::PrivateKey.new(
            key_pair_id,
            wrap_bytes(VirgilKeyPair.privateKeyToDER(native_key_pair.privateKey))
          )
          public_key = Keys::PublicKey.new(
            key_pair_id,
            wrap_bytes(VirgilKeyPair.publicKeyToDER(native_key_pair.publicKey))
          )
          return Keys::KeyPair.new(private_key, public_key)
        end

        # Imports the Private key from material representation.
        #
        # Args:
        #   key_bytes: key material representation bytes.
        #   password: private key password, nil by default.
        #
        # Returns:
        #   Imported private key.
        def import_private_key(key_bytes, password=nil)
          decrypted_private_key = nil
          if !password
            decrypted_private_key = VirgilKeyPair.privateKeyToDER(key_bytes)
          else
            decrypted_private_key = VirgilKeyPair.decryptPrivateKey(
              key_bytes,
              password.bytes
              #Virgil::SDK::Bytes.from_string(password)
            )
          end

          public_key_bytes = VirgilKeyPair.extractPublicKey(
            decrypted_private_key, []
          )
          key_pair_id = self.compute_public_key_hash(public_key_bytes)
          private_key_bytes = VirgilKeyPair.privateKeyToDER(decrypted_private_key)
          return Keys::PrivateKey.new(key_pair_id, wrap_bytes(private_key_bytes))
        end

        # Imports the Public key from material representation.
        #
        # Args:
        #   key_bytes: key material representation bytes.
        #
        # Returns:
        #   Imported public key.
        def import_public_key(key_bytes)
          key_pair_id = self.compute_public_key_hash(key_bytes)
          public_key_bytes = VirgilKeyPair.publicKeyToDER(key_bytes)
          Keys::PublicKey.new(key_pair_id, wrap_bytes(public_key_bytes))
        end

        # Exports the Private key into material representation.
        #
        # Args:
        #   private_key: private key for export.
        #   password: private key password, nil by default.
        #
        # Returns:
        #   Key material representation bytes.
        def export_private_key(private_key, password=nil)
          unless password
            return VirgilKeyPair.privateKeyToDER(private_key.value)
          end

          password_bytes = Virgil::SDK::Bytes.from_string(password)
          private_key_bytes = VirgilKeyPair.encryptPrivateKey(
            private_key.value,
            password_bytes
          )
          wrap_bytes(
            VirgilKeyPair.privateKeyToDER(private_key_bytes, password_bytes)
          )
        end

        # Exports the Public key into material representation.
        #
        # Args:
        #   public_key: public key for export.
        #
        # Returns:
        #   Key material representation bytes.
        def export_public_key(public_key)
          wrap_bytes(VirgilKeyPair.publicKeyToDER(public_key.value))
        end

        # Extracts the Public key from Private key.
        #
        # Args:
        #   private_key: source private key for extraction.
        #
        # Returns:
        #   Exported public key.
        def extract_public_key(private_key)
          public_key_bytes = VirgilKeyPair.extractPublicKey(
            private_key.value,
            []
          )
          Keys::PublicKey.new(
            private_key.receiver_id,
            wrap_bytes(VirgilKeyPair.publicKeyToDER(public_key_bytes))
          )
        end

        # Encrypts the specified bytes using recipients Public keys.
        #
        # Args:
        #   bytes: raw data bytes for encryption.
        #   recipients: list of recipients' public keys.
        #
        # Returns:
        #   Encrypted bytes bytes.
        def encrypt(bytes, *recipients)
          cipher = VirgilCipher.new
          recipients.each do |public_key|
            cipher.addKeyRecipient(public_key.receiver_id, public_key.value)
          end
          wrap_bytes(cipher.encrypt(bytes))
        end

        # Decrypts the specified bytes using Private key.
        #
        # Args:
        #   bytes: encrypted bytes bytes for decryption.
        #   private_key: private key for decryption.
        #
        # Returns:
        #   Decrypted bytes bytes.
        def decrypt(cipher_bytes, private_key)
          cipher = VirgilCipher.new
          decrypted_bytes = cipher.decryptWithKey(
            cipher_bytes,
            private_key.receiver_id,
            private_key.value
          )
          wrap_bytes(decrypted_bytes)
        end

        # Signs and encrypts the data.
        #
        # Args:
        #   bytes: data bytes for signing and encryption.
        #   private_key: private key to sign the data.
        #   recipients: list of recipients' public keys.
        #     Used for data encryption.
        #
        # Returns:
        #   Signed and encrypted data bytes.
        def sign_then_encrypt(bytes, private_key, *recipients)
          signer = VirgilSigner.new
          signature = signer.sign(bytes, private_key.value)
          cipher = VirgilCipher.new
          custom_bytes = cipher.customParams
          custom_bytes.setData(
            CUSTOM_PARAM_KEY_SIGNATURE,
            signature
          )
          recipients.each do |public_key|
            cipher.addKeyRecipient(public_key.receiver_id, public_key.value)
          end
          wrap_bytes(cipher.encrypt(bytes))
        end

        # Decrypts and verifies the data.
        #
        # Args:
        #   bytes: encrypted data bytes.
        #   private_key: private key for decryption.
        #   public_key: public key for verification.
        #
        # Returns:
        #   Decrypted data bytes.
        #
        # Raises:
        #   SignatureIsNotValid: if signature is not verified.
        def decrypt_then_verify(bytes, private_key, public_key)
          cipher = VirgilCipher.new
          decrypted_bytes = cipher.decryptWithKey(
            bytes,
            private_key.receiver_id,
            private_key.value
          )
          signature = cipher.customParams.getData(CUSTOM_PARAM_KEY_SIGNATURE)
          is_valid = self.verify(decrypted_bytes, signature, public_key)
          unless is_valid
            raise SignatureIsNotValid.new
          end
          wrap_bytes(decrypted_bytes)
        end

        # Signs the specified data using Private key.
        #
        # Args:
        #   bytes: raw data bytes for signing.
        #   private_key: private key for signing.
        #
        # Returns:
        #   Signature data.
        def sign(bytes, private_key)
          signer = VirgilSigner.new
          wrap_bytes(signer.sign(bytes, private_key.value))
        end

        # Verifies the specified signature using original data and signer's public key.
        #
        # Args:
        #   bytes: original data bytes for verification.
        #   signature: signature bytes for verification.
        #   signer_public_key: signer public key for verification.
        #
        # Returns:
        #   True if signature is valid, False otherwise.
        def verify(bytes, signature, signer_public_key)
          signer = VirgilSigner.new
          signer.verify(bytes, signature, signer_public_key.value)
        end

        # Encrypts the specified stream using recipients Public keys.
        #
        # Args:
        #   input_stream: readable stream containing input bytes.
        #   output_stream: writable stream for output.
        #   recipients: list of recipients' public keys.
        def encrypt_stream(input_stream, output_stream, *recipients)
          cipher = VirgilChunkCipher.new
          recipients.each do |public_key|
            cipher.addKeyRecipient(public_key.receiver_id, public_key.value)
          end
          source = VirgilStreamDataSource.new(input_stream)
          sink = VirgilStreamDataSink.new(output_stream)
          wrap_bytes(cipher.encrypt(source, sink))
        end

        # Decrypts the specified stream using Private key.
        #
        # Args:
        #   input_stream: readable stream containing input data.
        #   output_stream: writable stream for output.
        #   private_key: private key for decryption.
        def decrypt_stream(input_stream, output_stream, private_key)
          cipher = VirgilChunkCipher.new
          source = VirgilStreamDataSource.new(input_stream)
          sink = VirgilStreamDataSink.new(output_stream)
          cipher.decryptWithKey(
            source,
            sink,
            private_key.receiver_id,
            private_key.value
          )
        end

        # Signs the specified stream using Private key.
        #
        # Args:
        #   input_stream: readable stream containing input data.
        #   private_key: private key for signing.
        #
        # Returns:
        #   Signature bytes.
        def sign_stream(input_stream, private_key)
          signer = VirgilStreamSigner
          source = VirgilStreamDataSource.new(input_stream)
          wrap_bytes(signer.sign(source, private_key.value))
        end

        # Verifies the specified signature using original stream and signer's Public key.
        #
        # Args:
        #   input_stream: readable stream containing input data.
        #   signature: signature bytes for verification.
        #   signer_public_key: signer public key for verification.
        #
        # Returns:
        #   True if signature is valid, False otherwise.
        def verify_stream(input_stream, signature, signer_public_key)
          signer = VirgilStreamSigner.new
          source = VirgilStreamDataSource.new(input_stream)
          signer.verify(source, signature, signer_public_key.value)
        end

        # Calculates the fingerprint.
        #
        # Args:
        #   bytes: data bytes for fingerprint calculation.
        #
        # Returns:
        #   Fingerprint of the source data.
        def calculate_fingerprint(bytes)
          hash_bytes = self.compute_hash(bytes, Hashes::HashAlgorithm::SHA256)
          Hashes::Fingerprint.new(hash_bytes)
        end

        # Computes the hash of specified data.
        #
        # Args:
        #   bytes: data bytes for fingerprint calculation.
        #   algorithm: hashing algorithm.
        #     The possible values can be found in HashAlgorithm enum.
        #
        # Returns:
        #   Hash bytes.
        def compute_hash(bytes, algorithm)
          native_algorithm = Hashes::HashAlgorithm.convert_to_native(algorithm)
          native_hasher = VirgilHash.new(native_algorithm)
          wrap_bytes(native_hasher.hash(bytes))
        end

        # Computes the hash of specified public key using SHA256 algorithm.
        #
        # Args:
        #   public_key: public key for hashing.
        #
        # Returns:
        #   Hash bytes.
        def compute_public_key_hash(public_key)
          public_key_der = VirgilKeyPair.publicKeyToDER(public_key)
          self.compute_hash(public_key_der, Hashes::HashAlgorithm::SHA256)
        end

        private

        def wrap_bytes(raw_bytes)
          Virgil::SDK::Bytes.new(raw_bytes)
        end
      end
    end
  end
end
