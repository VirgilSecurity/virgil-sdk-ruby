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
    module API
      class VirgilKey
        attr_reader :context, :private_key

        def initialize(context, private_key)
          @context = context
          @private_key = private_key
        end

        # Decrypts the specified cipher data using Virgil key.
        #
        # Args:
        #   cipher_buffer: The encrypted data wrapped by VirgilBuffer.
        #
        # Returns:
        #   A byte array containing the result from performing the operation wrapped by VirgilBuffer.
        #
        # Raises:
        #   ArgumentError: buffer is not valid if buffer doesn't have type VirgilBuffer or String
        #   Recipient with given identifier is not found  if user tries to decrypt cipher data by private key,
        #     though its public key was not used for encryption
        def decrypt(cipher_buffer)
          raise ArgumentError.new("buffer is not valid") unless (cipher_buffer.is_a?(VirgilBuffer) || cipher_buffer.is_a?(String))

          bytes = context.crypto.decrypt(cipher_buffer.bytes, private_key)
          VirgilBuffer.new(bytes)
        end
      end
    end
  end
end