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
        # Base class for all cards API requests.
        class SignableRequest
          attr_reader :signatures, :snapshot, :validation_token, :relations


          # Constructs new {SignableRequest} object
          def initialize
            @signatures = {}
          end


          # Constructs snapshot model for exporting and signing.
          #   Should be implemented in the derived classes.
          # @raise [NotImplementedError]
          def snapshot_model
            raise NotImplementedError.new
          end


          # Restores request from snapshot model.
          #   Should be implemented in the derived classes.
          # @param snapshot [Hash] snapshot model
          # @raise [NotImplementedError]
          def restore_from_snapshot_model(snapshot)
            raise NotImplementedError.new
          end


          # Restores request from snapshot.
          # @param snapshot [Crypto::Bytes] Json-encoded snapshot request will be restored from.
          # @param signatures [Hash] Request signatures.
          # @param validation_token [String] validation token gotten from Virgil Identity Service.
          # @param relations [Hash] relations.
          # @return [SignableRequest] restored request.
          def restore(snapshot, signatures, validation_token = nil, relations = nil)
            @snapshot = snapshot
            @signatures = signatures
            @validation_token = validation_token
            @relations = relations
            model = JSON.parse(Crypto::Bytes.new(snapshot).to_s)
            restore_from_snapshot_model(model)
          end


          # Takes request data snapshot.
          #   Request snapshot bytes.
          def take_snapshot
            json_string = self.snapshot_model.to_json
            Crypto::Bytes.from_string(json_string)
          end


          # Exports request snapshot.
          # @return [String] base64-encoded json representation of the request model.
          def export
            json_string = self.request_model.to_json
            Base64.strict_encode64(json_string)
          end


          # Request data snapshot
          def snapshot
            @snapshot ||= self.take_snapshot
          end

          # Adds signature to request.
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
            if relations
              model[:meta][:relations] = relations
            end

            return model
          end
        end
      end
    end
  end
end
