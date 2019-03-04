# Copyright (C) 2015-2019 Virgil Security Inc.
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
# SERVICES; LOSS OF USE, bytes, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

module Virgil
  module Jwt

    # Provides payload for access token providers
    class TokenContext

      # Operation for which token is needed.
      # @return [String]
      attr_reader :operation

      # Identity that should be used in access token.
      # @return [String]
      attr_reader :identity

      # Service for which token is needed.
      # @return [String]
      attr_reader :service

      # You can set up token cache in {CallbackJwtProvider#obtain_access_token_proc}
      # and reset cached token if True.
      # @return [TrueClass] or [FalseClass]
      attr_reader :force_reload

      # Initializes a new instance of the class
      # @param operation [String] Operation for which token is needed
      # @param identity [String] Identity to use in token
      # @param force_reload [TrueClass] or [FalseClass]
      # If you set up token cache in {CallbackJwtProvider#obtain_access_token_proc}
      # it should reset cached token and return new if TRUE.
      def initialize(operation:, identity:, service: nil, force_reload: false)
        @operation = operation
        @identity = identity
        @service = service
        @force_reload = force_reload
      end
    end
  end
end