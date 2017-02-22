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

module Virgil
  module SDK
    module Client
      # Class used for signing high_level requests.
      class RequestSigner
        attr_reader :crypto

        # Constructs new RequestSigner object
        def initialize(crypto)
          @crypto = crypto
        end

        # Sign passed request with private key.
        #
        # Args:
        #     signable_request: request for signing.
        #     private_key: private key to sign with.
        def self_sign(signable_request, private_key)
          fingerprint = self.crypto.calculate_fingerprint(
            signable_request.snapshot
          )
          signature = self.crypto.sign(
            fingerprint.value,
            private_key
          )

          signable_request.sign_with(
            fingerprint.to_hex,
            signature
          )
        end

        # Sign passed request with authority private key.
        #
        # Args:
        #     signable_request: request for signing.
        #     signer_id: authority id.
        #     private_key: authority private key to sign with.
        def authority_sign(signable_request, signer_id, private_key)
          fingerprint = self.crypto.calculate_fingerprint(
            signable_request.snapshot
          )
          signature = self.crypto.sign(
            fingerprint.value,
            private_key
          )

          signable_request.sign_with(
            signer_id,
            signature
          )
        end
      end
    end
  end
end
