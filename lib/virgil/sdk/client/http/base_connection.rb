# Copyright (C) 2016 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   (1) Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
#   (2) Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
#   (3) Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
require 'faraday'
require 'faraday_middleware'
require 'json'

module Virgil
  module SDK
    module Client
      module HTTP
        # Base API service connection class.
        class BaseConnection
          class ApiError < StandardError
          end

          ERRORS = {}

          attr_accessor :access_token, :base_url

          # Constructs new BaseConnection object.
          def initialize(access_token, base_url)
            self.access_token = access_token
            self.base_url = base_url
          end

          # Sends http request to the endpoint.
          #
          # Args:
          #   request: HTTP::Request object containing sending request data.
          #
          # Returns:
          #   Deserialized ruby object from the json response.
          #
          # Raises:
          #   HTTPError with error message decoded from errors dictionary.
          def send_request(request)
            response = faraday_connection.run_request(
                request.method,
                request.endpoint,
                request.body,
                request.headers
            )
            return response.body if response.success?

            raise ApiError.new(error_message(response))

          end

          private

          def faraday_connection
            @faraday_connection ||= Faraday.new(url: base_url) do |connection|
              if access_token
                connection.authorization :VIRGIL, access_token
              end
              connection.request :json
              connection.response :json, :content_type => /\bjson$/
              connection.response :follow_redirects
              connection.adapter Faraday.default_adapter
            end
          end


          def error_message(response)
            error_message = nil
            error_body = response.body
            if error_body
              error_body = JSON.parse(error_body) unless error_body.is_a? Hash
              error_code = error_body['code'] ||
                  (error_body['error'] && error_body['error']['code'])
              error_message = self.class::ERRORS[error_code] || error_code
            end
            # token = attempt.confirm(emailConfirmation)
            error_message = "Error code is #{response.status}" unless error_message
            error_message
          end
        end
      end
    end
  end
end
