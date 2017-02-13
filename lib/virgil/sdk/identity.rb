module Virgil
  module SDK
    module Identity
      autoload :VerificationAttempt, 'virgil/sdk/identity/verification_attempt'
      autoload :VerificationOptions, 'virgil/sdk/identity/verification_options'
      autoload :ValidationToken, 'virgil/sdk/identity/validation_token'
      autoload :EmailConfirmation, 'virgil/sdk/identity/email_confirmation'

      IDENTITY_SERVICE_URL = "https://identity.virgilsecurity.com"

    end
  end
end