module ClientTestConfig
  DATA_DIR = File.expand_path('../../data', __FILE__)

  class << self
    def access_token
      @_access_token ||= ENV["VIRGIL_ACCESS_TOKEN"]
    end

    def app_id
      @_app_id ||= ENV["VIRGIL_APP_ID"]
    end

    def app_bundle
      @_app_bundle ||= ENV["VIRGIL_APP_BUNDLE"]
    end

    def app_key_path
      @_app_key_path ||= ENV["VIRGIL_APP_KEY_PATH"]
    end

    def app_key_password
      @_app_key_password ||= ENV["VIRGIL_APP_KEY_PASSWORD"]
    end

    def raw_app_private_key
      @_raw_app_private_key ||= File.read(app_key_path)
    end
  end
end
