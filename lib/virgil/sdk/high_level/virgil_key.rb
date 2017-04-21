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

        # manages the VirgilApi dependencies during run time.
        # @return [VirgilContext]
        attr_reader :context

        # private key
        # @return [Cryptography::Keys::PrivateKey]
        attr_reader :private_key

        # Initializes a new instance of the {VirgilKey} class.
        def initialize(context, private_key)
          @context = context
          @private_key = private_key
        end


        # Decrypts the specified cipher data using Virgil key.
        # @param cipher_buffer [VirgilBuffer, String, Crypto::Bytes] The encrypted data wrapped by VirgilBuffer or
        #                  encrypted data in base64-encoded String
        #                  or Array of bytes of encrypted data
        # @return [VirgilBuffer] A byte array containing the result from performing the action wrapped by VirgilBuffer.
        # @raise [ArgumentError] if buffer doesn't have type VirgilBuffer, base64-encoded String or Array of bytes
        # @example
        #   virgil = VirgilApi.new
        #   # load a Virgil Key from device storage
        #   alice_key = virgil.keys.load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")
        #
        #   # decrypt a buffer using loaded Virgil Key
        #   original_file_buf = alice_key.decrypt(cipher_file_buf)
        # @see VirgilCard#encrypt How to get cipher_file_buf
        # @see VirgilKeyManager#load Load Virgil Key
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
        # @param buffer [VirgilBuffer, String, Crypto::Bytes] The data for which the digital signature will be generated.
        #           buffer can be VirgilBuffer, utf8-encoded String or Array of bytes
        # @return [VirgilBuffer] A new buffer that containing the result from performing the action.
        # @raise [ArgumentError] if buffer doesn't have type VirgilBuffer, String or Array of bytes
        # @example
        #   virgil = VirgilApi.new
        #   # load Alice's Key from protected storage
        #   alice_key = virgil.keys.load("[KEY_NAME]", "[KEY_PASSWORD]")
        #
        #   message = "Hi Bob, hope you are doing well."
        #
        #   # generate signature of message using alice's key pair
        #   signature = alice_key.sign(message)
        # @see VirgilKeyManager#load Load the VirgilKey from current storage by specified key name.
        # @see VirgilCard#verify Verifies the specified buffer and signature with current VirgilCard recipient
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
        # @param buffer [VirgilBuffer, String, Crypto::Bytes] The data wrapped by VirgilBuffer to be encrypted and signed
        #     buffer can be VirgilBuffer, utf8-encoded String or Array of bytes
        # @param recipients [Array<VirgilCard>] The list of VirgilCard recipients.
        # @return [VirgilBuffer] A new buffer that containing the encrypted and signed data
        # @raise [ArgumentError] if buffer doesn't have type VirgilBuffer, String or Array of bytes
        # @raise [ArgumentError] if recipients doesn't have type Array or empty
        # @example Alice signs the message and encrypt it for Bob
        #   virgil = VirgilApi.new(access_token: "[YOUR_ACCESS_TOKEN_HERE]")
        #   # load a Virgil Key from device storage
        #   alice_key = virgil.keys.load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")
        #
        #   # search for Virgil Cards
        #   bob_cards = await virgil.cards.find("bob")
        #
        #   # prepare the message
        #   message = "Hey Bob, how's it going?"
        #
        #   # sign then encrypt the message
        #   ciphertext = alice_key.sign_then_encrypt(message, bob_cards).to_base64
        # @see VirgilKeyManager#load Load key from the key storage
        # @see VirgilCardManager#find Find card
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
        # @param cipher_buffer [VirgilBuffer, String, Crypto::Bytes] The data to be decrypted and verified:
        #                  The encrypted data wrapped by VirgilBuffer or
        #                  encrypted data in base64-encoded String
        #                  or Array of bytes of encrypted data
        # @param *cards [Array<VirgilCard>]  The list of trusted Virgil Cards, which can contains the signer's VirgilCard
        # @return [VirgilBuffer]The decrypted data, which is the original plain text before encryption
        #   the decrypted data, wrapped by VirgilBuffer
        # @raise [ArgumentError] if buffer doesn't have type VirgilBuffer, String or Array of bytes
        # @raise [ArgumentError] if recipients doesn't have type Array or empty
        # @example
        #   virgil = VirgilApi.new(access_token: "[YOUR_ACCESS_TOKEN_HERE]")
        #   # load a Virgil Key from device storage
        #   bob_key = virgil.keys.load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")
        #
        #   # get a sender's Virgil Card
        #   alice_card = virgil.cards.get("[ALICE_CARD_ID]")
        #
        #   # decrypt the message
        #   original_message = bob_key.decrypt_then_verify(ciphertext, alice_card).to_s
        def decrypt_then_verify(cipher_buffer, *cards)

          raise ArgumentError.new("card is not valid") unless cards.all? { |el| el.is_a? VirgilCard }

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

          public_keys = cards.map(&:public_key)
          bytes = context.crypto.decrypt_then_verify(buffer_to_decrypt.bytes, private_key, *public_keys)
          VirgilBuffer.new(bytes)
        end


        # Saves a current VirgilKey in secure storage.
        # @param key_name [String] The name of the key.
        # @param key_password [String] The key password.
        # @return [VirgilKey]
        # @raise [KeyEntryAlreadyExistsException] if key storage already has item with such name
        # @raise [ArgumentError] key_name is not valid if key_name is nil
        # @raise [KeyStorageException] if destination folder doesn't exist or you don't have permission to write there
        # @example
        #   virgil = VirgilApi.new
        #   alice_key = virgil.keys.generate.save("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")
        # @see VirgilKeyManager#generate How to generate key
        def save(key_name, key_password=nil)

          raise ArgumentError.new("key_name is not valid") if key_name.nil?

          exported_private_key = context.crypto.export_private_key(private_key, key_password)
          storage_item = Cryptography::Keys::StorageItem.new(key_name, exported_private_key)
          context.key_storage.store(storage_item)
          self

        end


        # Exports the VirgilKey to default format, specified in Crypto API.
        # @return [VirgilBuffer] Private Key material representation bytes wrapped by VirgilBuffer
        #
        # @example Export the Virgil Key to Base64 encoded string.
        #   virgil = VirgilApi.new
        #   # generate a new Virgil Key
        #   alice_key = virgil.keys.generate
        #
        #   # export the Virgil Key to Base64 encoded string
        #   BASE64_ENCODED_VIRGIL_KEY = alice_key.export("[OPTIONAL_KEY_PASSWORD]”).to_base64
        # @see VirgilKeyManager#generate How to generate key
        def export(password=nil)
          VirgilBuffer.from_bytes(context.crypto.export_private_key(private_key, password))
        end


        # Exports the Public key value from current VirgilKey.
        # @return [VirgilBuffer] A new VirgilBuffer that contains Public Key value.
        def export_public_key
          public_key = context.crypto.extract_public_key(private_key)
          VirgilBuffer.from_bytes(context.crypto.export_public_key(public_key))
        end

      end
    end
  end
end