module Virgil
  module SDK
    module HighLevel
      module VirgilIdentity
        autoload :VerificationAttempt, 'virgil/sdk/high_level/virgil_identity/verification_attempt'
        autoload :VerificationOptions, 'virgil/sdk/high_level/virgil_identity/verification_options'
        autoload :ValidationToken, 'virgil/sdk/high_level/virgil_identity/validation_token'
        autoload :EmailConfirmation, 'virgil/sdk/high_level/virgil_identity/email_confirmation'

        IDENTITY_SERVICE_URL = ENV["VIRGIL_IDENTITY_SERVICE_URL"] || "https://identity.virgilsecurity.com"

        EMAIL = "email"
        USERNAME = "username"
      end
    end
  end
end