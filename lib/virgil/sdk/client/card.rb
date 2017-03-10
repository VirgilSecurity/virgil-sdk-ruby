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
require 'base64'
require 'json'
module Virgil
  module SDK
    module Client
      # Model representing cards information.
      Card = Struct.new(:id, :snapshot, :identity,
                        :identity_type, :public_key, :scope,
                        :data, :device, :device_name, :version,
                        :signatures, :validation_token, :relations) do


        def initialize(options)
          self.id = options[:id]
          self.snapshot = options[:snapshot]
          self.identity = options[:identity]
          self.identity_type = options[:identity_type]
          self.public_key = options[:public_key]
          self.scope = options[:scope]
          self.data = options[:data] || {}
          self.device = options[:device]
          self.device_name = options[:device_name]
          self.version = options[:version]
          self.signatures = options[:signatures] || {}
          self.relations = options[:relations] || {}
        end

        # Create new Card from response containing json-encoded snapshot.
        # Args:
        #     response: Cards service response containing base64 encoded content_snapshot.
        # Returns:
        #     Card model restored from snapshot.
        def self.from_response(response)
          snapshot = Base64.decode64(response["content_snapshot"])
          snapshot_model = JSON.parse(snapshot)
          info = snapshot_model.fetch("info", {}) || {}

          return new(
              id: response["id"],
              snapshot: snapshot,
              identity: snapshot_model["identity"],
              identity_type: snapshot_model["identity_type"],
              public_key: Virgil::Crypto::Bytes.from_base64(
                  snapshot_model["public_key"]
              ),
              device: info["device"],
              device_name: info["device_name"],
              data: snapshot_model.fetch("data", {}),
              scope: snapshot_model["scope"],
              version: response["meta"]["card_version"],
              signatures: response["meta"]["signs"],
              relations: response["meta"]["relations"]
          )
        end




        def to_request
          request = Virgil::SDK::Client::Requests::CreateCardRequest.new({})
          request.restore(Crypto::Bytes.from_string(snapshot), signatures, validation_token, relations)
          request
        end

        def export
          self.to_request.export
        end


        def self.from_request_model(request_model)
          snapshot = Base64.decode64(request_model[:content_snapshot])
          # if request_model[:content_snapshot].is_a?(Array)
          #   snapshot = Virgil::Crypto::Bytes.new(request_model[:content_snapshot]).to_s
          # end

          snapshot_model = JSON.parse(snapshot)
          meta = request_model[:meta]
          info = snapshot_model.fetch("info", {}) || {}
          return new(
              snapshot: snapshot,
              identity: snapshot_model["identity"],
              identity_type: snapshot_model["identity_type"],
              public_key: Virgil::Crypto::Bytes.from_base64(
                  snapshot_model["public_key"]
              ),
              device: info["device"],
              device_name: info["device_name"],
              data: snapshot_model.fetch("data", {}),
              scope: snapshot_model["scope"],
              signatures: meta[:signs],
              relations: meta[:relations]
          )
        end


      end

      Card::APPLICATION = "application"
      Card::GLOBAL = "global"




      Card::SERVICE_URL = "https://cards.virgilsecurity.com"
      Card::READ_ONLY_SERVICE_URL = "https://cards-ro.virgilsecurity.com"
      Card::RA_SERVICE_URL = "https://ra.virgilsecurity.com"
      Card::VRA_VERSION = "v1" # version of service, which creates and deletes local and global cards
      Card::VC_VERSION = "v4" # version of service, which gets, searchs card
    end
  end
end
