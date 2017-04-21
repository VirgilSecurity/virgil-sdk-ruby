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
      # this class provides a list of methods to generate the VirgilKey
      # and further them storage in secure place.
      class VirgilKeyManager

        # manages the VirgilApi dependencies during run time.
        # @return [VirgilContext]
        attr_reader :context

        # Initializes a new instance of the {VirgilKeyManager} class.
        def initialize(context)
          @context = context
        end


        # Generates a new {VirgilKey} with default parameters.
        # @return [VirgilKey]
        # @example Generate Virgil Key
        #   virgil = VirgilApi.new
        #   alice_key = virgil.keys.generate
        #   # After generation you can save the key to key storage
        #
        # @example GENERATE A VIRGIL KEY WITH A SPECIFIC TYPE
        #   initialize Crypto with specific key pair type
        #   crypto = VirgilCrypto.new(KeyPairType::EC_BP512R1)
        #
        #   context = VirgilContext.new(crypto: crypto)
        #
        #   # initialize Virgil SDK using context
        #   virgil = VirgilApi.new(context: context)
        #
        #   # generate a new Virgil Key
        #   alice_key = virgil.keys.generate()
        # @see VirgilKey#save  Save a current VirgilKey in secure storage.
        def generate
          key_pair = context.crypto.generate_keys()
          VirgilKey.new(context, key_pair.private_key)
        end


        # Loads the VirgilKey from current storage by specified key name.
        # @param key_name [String] The name of the key.
        # @param key_password [String]
        # @return [VirgilKey]
        # @raise [KeyEntryNotFoundException] if key storage doesn't have item with such name
        # @raise [ArgumentError] if key_name is nil
        # @raise [KeyStorageException] if destination folder doesn't exist or you don't have permission to write there
        # @example
        #   virgil = VirgilApi.new()
        #   # load a Virgil Key from storage
        #   alice_key = virgil.keys.load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")
        def load(key_name, key_password=nil)

          raise ArgumentError.new("key_name is not valid") if key_name.nil?

          storage_item = context.key_storage.load(key_name)
          private_key = context.crypto.import_private_key(storage_item.data, key_password)
          VirgilKey.new(context, private_key)

        end

        # Imports the {VirgilKey} from buffer.
        # @param buffer [VirgilBuffer] The buffer with Key
        # @param password [String] The Key password
        # @return [VirgilKey]
        # @example
        #   virgil = VirgilApi.new
        #   # initialize a buffer from base64 encoded string
        #   alice_key_buffer = VirgilBuffer.from_base64("[BASE64_ENCODED_VIRGIL_KEY]")
        #
        #   # import Virgil Key from buffer
        #   alice_key = virgil.keys.import(alice_key_buffer, "[OPTIONAL_KEY_PASSWORD]")
        # @see VirgilKey.export How to get BASE64_ENCODED_VIRGIL_KEY
        def import(buffer, password=nil)
          private_key = context.crypto.import_private_key(buffer.bytes, password)
          VirgilKey.new(context, private_key)
        end


        # Remove the {VirgilKey} from current storage by specified key name.
        # @param key_name [String] The name of the key.
        # @raise [KeyEntryNotFoundException] if key storage doesn't have item with such name
        # @raise [ArgumentError] if key_name is nil
        # @raise [KeyStorageException] if destination folder doesn't exist or you don't have permission to write there
        # @example Remove key from the storage by name
        #   virgil = VirgilApi.new
        #   virgil.keys.delete("[KEY_NAME]")
        def delete(key_name)

          raise ArgumentError.new("key_name is not valid") if key_name.nil?

          context.key_storage.delete(key_name)
        end

      end
    end
  end
end
