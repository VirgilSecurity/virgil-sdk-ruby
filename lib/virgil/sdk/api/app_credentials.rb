module Virgil
  module SDK
    module API
      class AppCredentials
        attr_accessor :app_id, :app_key_data, :app_key_password

        def initialize(app_id:, app_key_data:, app_key_password:)
          self.app_id = app_id
          self.app_key_data = app_key_data
          self.app_key_password = app_key_password
        end
      end
    end
  end
end


