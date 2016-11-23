require 'base64'

module Virgil
  module SDK
    class Bytes < Array
      def self.from_string(source)
        new(source.bytes.to_a)
      end

      def self.from_base64(source)
        new(Base64.decode64(source).bytes)
      end
    end
  end
end
