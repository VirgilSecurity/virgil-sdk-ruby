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
require 'fileutils'

module Virgil
  module SDK
    module Cryptography
      module Keys
        class KeyStorage

          attr_reader :folder_path

          class KeyStorageException < StandardError

          end

          class KeyEntryAlreadyExistsException < KeyStorageException

            def to_s
              "Storage key entry already exists"
            end

          end

          class KeyEntryNotFoundException < KeyStorageException

            def to_s
              "Storage key entry isn't found"
            end

          end

          def initialize(folder_path=self.class.default_folder)

            raise ArgumentError.new("folder_path is not valid") if (!folder_path.is_a?(String) || folder_path.empty?)

            @folder_path = folder_path
            validate_storage_folder

          end


          def self.default_folder
            path = "./key_storage"
            FileUtils.mkdir(path) unless Dir.exist?(path)
            path
          end


          # Stores the key to the given alias.
          #
          # Args:
          #   storage_item: The storage item to be kept
          #
          # Raises:
          #   KeyEntryAlreadyExistsException: if key storage already has item with such name
          def store(storage_item)

            validate_storage_folder
            if exists?(storage_item.name)
              raise KeyEntryAlreadyExistsException.new
            end

            open(item_file_path(storage_item.name), 'w') do |f|
              f.write(storage_item.to_json)
              File.chmod(0400, item_file_path(storage_item.name))
            end

          end


          # Loads the key associated with the given alias.
          #
          # Args:
          #   item_name: The alias name.
          #
          # Returns:
          #   The requested key, or null if the given alias does not exist or does
          #    not identify a key-related entry.
          #
          # Raises:
          #   KeyEntryNotFoundException: if key storage doesn't have item with such name
          def load(item_name)

            validate_storage_folder
            raise KeyEntryNotFoundException.new unless exists?(item_name)

            json_body = File.read(item_file_path(item_name))
            return nil if json_body.nil?

            StorageItem.restore_from_json(item_name, json_body)

          end


          # Checks if the given alias exists in this keystore.
          #
          # Args:
          #   item_name: The alias name.
          #
          # Returns:
          #   true if the given alias exists in this keystore.
          #   false if the given alias doesn't exist in this keystore.
          def exists?(item_name)

            File.exist?(item_file_path(item_name))

          end


          # Delete the key associated with the given alias.
          #
          # Args:
          #   item_name: The alias name.
          #
          # Raises:
          #   KeyEntryNotFoundException: if key storage doesn't have item with such name
          def delete(item_name)

            validate_storage_folder
            raise KeyEntryNotFoundException.new unless exists?(item_name)

            File.delete(item_file_path(item_name))

          end


          private

          def validate_storage_folder

            unless (Dir.exist?(folder_path) && File.writable?(folder_path) && File.readable?(folder_path))
              raise KeyStorageException.new("Destination folder doesn't exist or you don't have permission to write there")
            end

          end

          def item_file_path(item_name)

            File.join(folder_path, item_name)

          end
        end
      end
    end
  end
end