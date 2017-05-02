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
      # Class holds criteria for searching Cards.
      SearchCriteria = Struct.new(:identities, :identity_type, :scope) do
        def initialize(identities, identity_type=nil, scope=nil)
          super
        end

        # Create new search criteria for searching cards by identity.
        # @param identity [String] VirgilIdentity value.
        # @return [SearchCriteria] Search criteria with provided identity.
        def self.by_identity(identity)
          return self.by_identities([identity])
        end

        # Create new search criteria for searching cards by identities.
        # @param identities [Array<String>] Identities value.
        # @return [SearchCriteria] Search criteria with provided identities.
        def self.by_identities(identities)
          return new(identities, nil, Card::APPLICATION)
        end

        # Create new search criteria for searching cards by application bundle.
        # @param bundle [String] Application bundle.
        # @return [SearchCriteria] Search criteria for searching by bundle.
        def self.by_app_bundle(bundle)
          return new([bundle], 'application', Card::GLOBAL)
        end
      end
    end
  end
end
