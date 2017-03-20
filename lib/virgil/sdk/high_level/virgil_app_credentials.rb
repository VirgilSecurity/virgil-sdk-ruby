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

      # This class provides credentials for application authentication using AppID and AppKey
      # retrieved from development deshboard.
      class VirgilAppCredentials

        # uniquely identifies your application in Virgil services, and it is also used to identify the
        # Virgil Card/Public key generated in a pair with application key.
        attr_reader :app_id

        # Application Private key value wrapped by an instance of the {VirgilBuffer} class.
        attr_reader :app_key_data

        # Application key password is used to protect the application key.
        attr_reader :app_key_password

        # Initializes a new instance of the {VirgilAppCredentials} class
        def initialize(app_id:, app_key_data:, app_key_password:)
          @app_id = app_id
          @app_key_data = app_key_data
          @app_key_password = app_key_password
        end

        # Application key is representing a Private key that is used to perform creation and revocation of Virgil Cards
        # (Public key) in Virgil services. Also the application key can be used for cryptographic operations to take part
        # in application logic.
        def app_key(crypto)
          crypto.import_private_key(app_key_data.bytes, app_key_password)
        end
      end
    end
  end
end


