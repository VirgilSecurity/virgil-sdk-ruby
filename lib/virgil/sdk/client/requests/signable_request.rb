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

require 'json'
require 'base64'

module Virgil
  module SDK
    module Client
      module Requests
        # Base class for all API requests.
        class SignableRequest
          extend SignaturesBase64
          attr_reader :signatures, :snapshot, :validation_token

          # protected :signatures=, :snapshot=
          # attr_writer :snapshot

          # Constructs new SignableRequest object
          def initialize
            @signatures = {}
          end

          # Constructs snapshot model for exporting and signing.
          #
          # Should be implemented in the derived classes.
          #
          # Raises:
          #   NotImplementedError
          def snapshot_model
            raise NotImplementedError.new
          end

          # Restores request from snapshot model.
          #
          # Should be implemented in the derived classes.
          #
          # Args:
          #   snapshot: snapshot model dict
          #
          # Raises:
          #   NotImplementedError
          def restore_from_snapshot_model(snapshot)
            raise NotImplementedError.new
          end


          # Restores request from snapshot.
          #
          #  Args:
          #    snapshot: Json-encoded snapshot request will be restored from.
          #    signatures: Request signatures.
          def restore(snapshot, signatures, validation_token = nil)
            @snapshot = snapshot
            @signatures = signatures
            @validation_token = validation_token
            model = JSON.parse(Crypto::Bytes.new(snapshot).to_s)
            restore_from_snapshot_model(model)
          end


          # Takes request data snapshot.
          #
          # Returns:
          #   Request snapshot bytes.
          def take_snapshot
            json_string = self.snapshot_model.to_json
            Crypto::Bytes.from_string(json_string)
          end


          # Exports request snapshot.
          #
          # Returns:
          #   base64-encoded json representation of the request model.
          def export
            json_string = self.request_model.to_json
            Base64.strict_encode64(json_string)
          end


          # Request data snapshot
          def snapshot
            @snapshot ||= self.take_snapshot
          end

          # Adds signature to request."""
          def sign_with(fingerprint_id, signature)
            @signatures[fingerprint_id] = signature
          end

          # Request model used for json representation.
          def request_model
            model = {
              'content_snapshot': Base64.strict_encode64(snapshot.to_s),
              'meta': {
                'signs': signatures
              }
            }

            if validation_token
              model[:meta][:validation] = {'token': validation_token.value}
            end

            return model
          end
        end
      end
    end
  end
end
