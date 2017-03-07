module Virgil
  module SDK
    module HighLevel
    autoload :VirgilApi, 'virgil/sdk/high_level/virgil_api'
    autoload :VirgilIdentity, 'virgil/sdk/high_level/virgil_identity'
    autoload :VirgilCard, 'virgil/sdk/high_level/virgil_card'
    autoload :VirgilKey, 'virgil/sdk/high_level/virgil_key'
    autoload :VirgilContext, 'virgil/sdk/high_level/virgil_context'
    autoload :VirgilKeyManager, 'virgil/sdk/high_level/virgil_key_manager'
    autoload :VirgilCardManager, 'virgil/sdk/high_level/virgil_card_manager'
    autoload :VirgilAppCredentials, 'virgil/sdk/high_level/virgil_app_credentials'
    autoload :VirgilBuffer, 'virgil/sdk/high_level/virgil_buffer'
    autoload :VirgilStringEncoding, 'virgil/sdk/high_level/virgil_buffer'
    autoload :VirgilCardVerifierInfo, 'virgil/sdk/high_level/virgil_card_verifier_info'

    VirgilCrypto = Virgil::SDK::Cryptography::VirgilCrypto
    KeyPairType = Virgil::SDK::Cryptography::Keys::KeyPairType
    end
  end
end

