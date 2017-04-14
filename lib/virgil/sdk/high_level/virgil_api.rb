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

      # The VirgilApi class is a high-level API that provides easy access to
      # Virgil Security services and allows to perform cryptographic operations by using two domain entities
      # VirgilKey and VirgilCard. Where the VirgilKey is an entity
      # that represents a user's Private key, and the VirgilCard is the entity that represents
      # user's identity and a Public key.
      class VirgilApi

        # Virgil Context that manages the VirgilApi dependencies during run time.
        # @return [VirgilContext]
        attr_accessor :context

        # Virgil Key Manager that provides a work with VirgilKey entities.
        # @return [VirgilKeyManager]
        attr_accessor :keys

        # Virgil Card Manager that provides a work with VirgilCard entities.
        # @return [VirgilCardManager]
        attr_accessor :cards

        class VirgilApiException < StandardError

        end

        class VirgilApiAccessTokenException < VirgilApiException

          def to_s
            "Access tokens are not equal"
          end

        end


        # Initializes a new instance of the {VirgilApi} class.
        # @param access_token: [String] Retrieved string value from development deshboard that provides an authenticated secure access to the
        #                   Virgil Security services. The access token also allows the API to associate
        #                   your app requests with your Virgil Security developer’s account.
        #                   It's not required if context with own access token has been set.
        #                   It's required(only if context with own access token hasn't been set)
        #                     for the following actions: get card, find card.
        # @param context: [VirgilContext] Virgil Context that manages the VirgilApi dependencies during run time.
        #                 It's required with defined Application credentials and own access_token for publishing and revoking card.
        #
        # @note The both of the arguments(access_token and context) are not required for actions with Global cards.
        def initialize(access_token: nil, context: nil)

          if (access_token && context)
            raise VirgilApiAccessTokenException.new unless access_token == context.access_token
          end


          if context
            self.context = context
          else
            self.context = Virgil::SDK::HighLevel::VirgilContext.new(access_token: access_token)
          end

          self.keys = VirgilKeyManager.new(self.context)
          self.cards = VirgilCardManager.new(self.context)
        end
      end
    end
  end
end