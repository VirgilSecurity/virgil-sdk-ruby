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
    module Client
      module Requests
        # Create card signable API request.
        class CreateCardRequest < SignableRequest
          attr_accessor :identity, :identity_type, :public_key, :data, :info, :scope

          # Constructs new CreateCardRequest object
          def initialize(attributes)
            super()
            self.identity = attributes[:identity]
            self.identity_type = attributes[:identity_type]
            self.public_key = attributes[:raw_public_key]
            self.scope = attributes[:scope] || Card::APPLICATION
            self.data = attributes[:data]
            self.info = attributes[:info]
          end

          # Restores request from snapshot model.
          #
          # Args:
          #   snapshot_model: snapshot model dict
          def restore_from_snapshot_model(snapshot_model)
            self.identity = snapshot_model['identity']
            self.identity_type = snapshot_model['identity_type']
            self.public_key = snapshot_model['public_key']
            self.scope = snapshot_model['scope']
            self.data = snapshot_model.fetch('data', {})
            self.info = snapshot_model['info']
          end


          def self.import(data_base64)
            request = new({})
            begin
              request_model = JSON.parse(Base64.decode64(data_base64))
            rescue JSON::ParserError => e
              raise ArgumentError.new("data_base64 is not valid")
            end
            validation_token = nil
            if request_model['meta']['validation'] && request_model['meta']['validation']['token']
              validation_token = Virgil::Crypto::Bytes.from_base64(request_model['meta']['validation']['token'])
            end
            request.restore(Virgil::Crypto::Bytes.from_base64(request_model['content_snapshot']),
                            request_model['meta']['signs'],
                            validation_token
            )
            request
          end

          # Constructs snapshot model for exporting and signing.
          #
          # Returns:
          #   Dict containing snapshot data model used for card creation request.
          def snapshot_model
            model = {
                'identity': identity,
                'identity_type': identity_type,
                'public_key': Virgil::Crypto::Bytes.new(public_key).to_base64,
                'scope': scope,
                'data': data
            }
            model['info'] = info if (info && info.any?)
            model
          end
        end
      end
    end
  end
end
