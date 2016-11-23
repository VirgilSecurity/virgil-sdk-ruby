require 'base64'
require 'json'

module Virgil
  module SDK
    class Bytes < Array
      def self.from_string(source)
        new(source.bytes.to_a)
      end

      def self.from_base64(source)
        new(Base64.decode64(source).bytes)
      end

      def to_s
        pack('c*')
      end

      def to_json(*a)
        Base64.strict_encode64(to_s).to_json(*a)
      end
    end
  end
end
