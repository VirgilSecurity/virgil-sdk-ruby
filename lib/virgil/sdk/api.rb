module Virgil
  module SDK
    module API
    autoload :Api, 'virgil/sdk/api/virgil_api'
    autoload :Card, 'virgil/sdk/client/card'
    autoload :VirgilCard, 'virgil/sdk/api/virgil_card'
    autoload :VirgilKey, 'virgil/sdk/api/virgil_key'
    autoload :Context, 'virgil/sdk/api/context'
    autoload :KeyManager, 'virgil/sdk/api/key_manager'
    autoload :CardManager, 'virgil/sdk/api/card_manager'
    autoload :AppCredentials, 'virgil/sdk/api/app_credentials'
    autoload :IdentityAttempt, 'virgil/sdk/api/identity_attempt'
    autoload :VirgilBuffer, 'virgil/sdk/api/virgil_buffer'
    autoload :StringEncoding, 'virgil/sdk/api/virgil_buffer'
    autoload :CardVerifierInfo, 'virgil/sdk/api/card_verifier_info'
    end
  end
end