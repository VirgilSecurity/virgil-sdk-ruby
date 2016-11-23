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
        # Revoke card signable API request.
        class RevokeCardRequest < SignableRequest

          # Class containing possible revocation reasons.
          class Reasons
            Unspecified = 'unspecified'
            Compromised = 'compromised'
          end

          attr_accessor :card_id, :reason

          # Constructs new CreateCardRequest object
          def initialize(attributes)
            super()
            self.card_id = attributes[:card_id]
            self.reason = attributes[:reason] || Reasons::Unspecified
          end

          # Restores request from snapshot model.
          #
          # Args:
          #   snapshot_model: snapshot model dict
          def restore_from_snapshot_model(snapshot_model)
            self.card_id = snapshot_model['card_id']
            self.reason = snapshot_model['revocation_reason']
          end

          # Constructs snapshot model for exporting and signing.
          #
          # Returns:
          #   Dict containing snapshot data model used for card revocation request.
          def snapshot_model
            return {
              'card_id': self.card_id,
              'revocation_reason': self.reason,
            }
          end
        end
      end
    end
  end
end
