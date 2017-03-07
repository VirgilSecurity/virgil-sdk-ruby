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
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
module Virgil
  module SDK
    module HighLevel
      # This class represents a user's high-level Private key which provides
      # a list of methods that allows to store the key and perform cryptographic operations like
      # Decrypt, Sign etc.
      class VirgilKey
        attr_reader :context, :private_key

        def initialize(context, private_key)
          @context = context
          @private_key = private_key
        end


        # Decrypts the specified cipher data using Virgil key.
        #
        # Args:
        #   cipher_buffer: The encrypted data wrapped by VirgilBuffer or
        #                  encrypted data in base64-encoded String
        #                  or Array of bytes of encrypted data
        #
        # Returns:
        #   A byte array containing the result from performing the operation wrapped by VirgilBuffer.
        #
        # Raises:
        #   ArgumentError: buffer is not valid if buffer doesn't have type VirgilBuffer, base64-encoded String or Array of bytes
        #   Recipient with given identifier is not found  if user tries to decrypt cipher data by private key,
        #     though its public key was not used for encryption
        def decrypt(cipher_buffer)

          buffer_to_decrypt = case cipher_buffer.class.name.split("::").last
                                when 'VirgilBuffer'
                                  cipher_buffer
                                when 'String'
                                  VirgilBuffer.from_base64(cipher_buffer)
                                when 'Array'
                                  VirgilBuffer.from_bytes(cipher_buffer)
                                else
                                  raise ArgumentError.new("Buffer has unsupported type")
                              end

          bytes = context.crypto.decrypt(buffer_to_decrypt.bytes, private_key)
          VirgilBuffer.new(bytes)
        end


        # Generates a digital signature for specified data using current Virgil key.
        #
        # Args:
        #   buffer: The data for which the digital signature will be generated.
        #           buffer can be VirgilBuffer, utf8-encoded String or Array of bytes
        #
        # Returns:
        #   A new buffer that containing the result from performing the operation.
        #
        # Raises:
        #   ArgumentError: Buffer has unsupported type if buffer doesn't have type VirgilBuffer, String or Array of bytes
        def sign(buffer)
          buffer_to_sign = case buffer.class.name.split("::").last
                             when 'VirgilBuffer'
                               buffer
                             when 'String'
                               VirgilBuffer.from_string(buffer)
                             when 'Array'
                               VirgilBuffer.from_bytes(buffer)
                             else
                               raise ArgumentError.new("Buffer has unsupported type")
                           end

          VirgilBuffer.new(context.crypto.sign(buffer_to_sign.bytes, private_key).to_s.bytes)
        end


        # Encrypts and signs the data.
        #
        # Args:
        #   buffer: The data wrapped by VirgilBuffer to be encrypted and signed
        #     recipients: The list of VirgilCard recipients.
        #     buffer can be VirgilBuffer, utf8-encoded String or Array of bytes
        #
        # Returns:
        #   A new buffer that containing the encrypted and signed data
        #

        # Raises:
        #   ArgumentError: Buffer has unsupported type if buffer doesn't have type VirgilBuffer, String or Array of bytes
        #   ArgumentError: recipients is not valid if recipients doesn't have type Array or empty
        def sign_then_encrypt(buffer, recipients)

          raise ArgumentError.new("recipients is not valid") if (!recipients.is_a?(Array) || recipients.empty?)
          buffer_to_sign = case buffer.class.name.split("::").last
                             when 'VirgilBuffer'
                               buffer
                             when 'String'
                               VirgilBuffer.from_string(buffer)
                             when 'Array'
                               VirgilBuffer.from_bytes(buffer)
                             else
                               raise ArgumentError.new("Buffer has unsupported type")
                           end
          public_keys = recipients.map(&:public_key)
          bytes = context.crypto.sign_then_encrypt(buffer_to_sign.bytes, private_key, *public_keys).to_s.bytes
          VirgilBuffer.new(bytes)

        end


        # Decrypts and verifies the data.
        #
        # Args:
        #   cipher_buffer: The data to be decrypted and verified:
        #                  The encrypted data wrapped by VirgilBuffer or
        #                  encrypted data in base64-encoded String
        #                  or Array of bytes of encrypted data
        #   card: The signer's VirgilCard
        #
        # Returns:
        #   The decrypted data, which is the original plain text before encryption The decrypted data, wrapped by VirgilBuffer
        #
        # Raises:
        #   ArgumentError: buffer is not valid if buffer doesn't have type VirgilBuffer, String or Array of bytes
        #   ArgumentError: recipients is not valid if recipients doesn't have type Array or empty
        def decrypt_then_verify(cipher_buffer, card)

          raise ArgumentError.new("card is not valid") unless card.is_a?(VirgilCard)

          buffer_to_decrypt = case cipher_buffer.class.name.split("::").last
                                when 'VirgilBuffer'
                                  cipher_buffer
                                when 'String'
                                  VirgilBuffer.from_base64(cipher_buffer)
                                when 'Array'
                                  VirgilBuffer.from_bytes(cipher_buffer)
                                else
                                  raise ArgumentError.new("Buffer has unsupported type")
                              end

          bytes = context.crypto.decrypt_then_verify(buffer_to_decrypt.bytes, private_key, card.public_key)
          VirgilBuffer.new(bytes)
        end


        #  Saves a current VirgilKey in secure storage.
        #
        # Args:
        #   key_name: The name of the key.
        #   key_password: The key password.
        #
        # Returns:
        #   An instance of VirgilKey class
        #
        # Raises:
        #    KeyEntryAlreadyExistsException: if key storage already has item with such name
        #   ArgumentError: key_name is not valid if key_name is nil
        #   KeyStorageException: Destination folder doesn't exist or you don't have permission to write there
        def save(key_name, key_password=nil)

          raise ArgumentError.new("key_name is not valid") if key_name.nil?

          exported_private_key = context.crypto.export_private_key(private_key, key_password)
          storage_item = Cryptography::Keys::StorageItem.new(key_name, exported_private_key)
          context.key_storage.store(storage_item)
          self

        end


        #  Exports the Public key value from current VirgilKey.
        #
        # Returns:
        #   A new VirgilBuffer that contains Public Key value.
        def export_public_key
          public_key = context.crypto.extract_public_key(private_key)
          VirgilBuffer.from_bytes(context.crypto.export_public_key(public_key))
        end

      end
    end
  end
end