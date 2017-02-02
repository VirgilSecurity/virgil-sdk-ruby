module Virgil
  module SDK
    module Client
      module SignaturesBase64

        def signatures_to_base64(signatures_bytes)
          encoded_signatures = {}
          signatures_bytes.each do |key, val|
            encoded_signatures[key] = Base64.strict_encode64(Virgil::Crypto::Bytes.new(val).to_s) #TODO
          end
          encoded_signatures
        end


        def signatures_from_base64(signatures_base64)
          decoded_signatures = {}
          signatures_base64.each do |key, val|
            decoded_signatures[key] = Virgil::Crypto::Bytes.from_base64(val)
          end
          decoded_signatures
        end
      end
    end
  end
end
