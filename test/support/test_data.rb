require 'json'

module TestData
  DATA_DIR = File.expand_path('../../data', __FILE__)

  class << self
    def compatibility_data
      @_compatibility_data ||= begin
         path = File.join(DATA_DIR, 'sdk_compatibility_data.json')
         raw_data = File.read(path)
         JSON.parse(raw_data)
      end
    end

    def card_verifier_data
      @_card_verifier_data ||= begin
        path = File.join(DATA_DIR, 'card_verifier_data.json')
        raw_data = File.read(path)
        JSON.parse(raw_data)
      end
    end

    def original_data_file_path
      @original_data_file_path ||= File.join(DATA_DIR, 'input.txt')
    end

    def encrypted_data_file_path
      @encrypted_data_file_path ||= File.join(DATA_DIR, 'encrypted.txt')
    end

    def decrypted_data_file_path
      @decrypted_data_file_path ||= File.join(DATA_DIR, 'output.txt')
    end

  end
end
