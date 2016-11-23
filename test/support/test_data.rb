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
  end
end
