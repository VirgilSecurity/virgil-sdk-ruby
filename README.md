# Virgil JWT
[![Gem](https://img.shields.io/gem/v/virgil-jwt.svg)](https://rubygems.org/gems/virgil-jwt)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [Library purposes](#library-purposes) | [Installation](#sdk-installation) | [Usage examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction
Virgil JSON Web Token ("JWT") allows you to make call to Virgil Services without having to know how they're constructed.

## Library purposes
* Authentication using tokens that are based on the [JSON Web Token standard](https://jwt.io) but with some Virgil modification.


## Installation

The Virgil JWT is provided as a [gem](https://rubygems.org/) named [*virgil-jwt*](https://rubygems.org/gems/virgil-jwt) and available for Ruby 2.1 and newer. The package is distributed via *bundler* package manager.
 
 To install the package use the command below:
 
 ```
 gem install virgil-crypto
 gem install virgil-jwt
 gem install base64url
 ```
 
 or add the following line to your Gemfile:
 
 ```
 gem 'virgil-crypto', '~> 3.6.2'
 gem 'virgil-jwt'
 ```
and then run

```
bundle
```

## Usage examples

#### Virgil developer credentials

Collect your Virgil developer credentials form [Virgil Dashboard](https://dashboard.virgilsecurity.com):
APP_ID, API_KEY_ID, API_KEY

| Parameter    |Description                                                                                                                                                                                                        |
|--------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| APP_ID       | ID of your Application at [Virgil Dashboard](https://dashboard.virgilsecurity.com)                                                                                                                                |
| API_KEY_ID   | A unique string value that identifies your account at the Virgil developer portal                                                                                                                                 |
| API_KEY      | A Private Key that is used to sign API calls to Virgil Services. For security, you will only be shown the API Private Key when the key is created. Don't forget to save it in a secure location for the next step |

Generate a Private Key with the default algorithm (EC_X25519):

```ruby
require 'virgil/crypto'
include Virgil::Crypto

crypto = VirgilCrypto.new
key_pair = crypto.generate_keys
```

### Set up Client side and send a JWT request
After a user installs Virgil Jwt you'll need to set up JWT Provider for providing a user with a JWT. You'll need to give your users a JWT that tells Virgil who they are and what they can do.
Requests to your app server must be authorized. You can use any kind of authentication, for example, Google auth.

#### Set up JWT provider
Use these lines of code to specify which JWT generation source you prefer to use in your project:

```ruby
require 'virgil/crypto'
require 'virgil/jwt'
include Virgil::Crypto
include Virgil::Jwt

# Get generated token from server-side
obtain_token_proc = proc { authenticated_query_to_server('my_token_identity').to_s }

# Setup AccessTokenProvider
access_token_provider = CallbackJwtProvider(obtain_token_proc)
```

### Set up Server Side and Generate JWT

Next, you'll set up the JwtGenerator and generate a JWT using the Virgil SDK.
You'll use your API Key that was created at Virgil Dashboard. For security purposes, you have to generate JWT on your server side.

Each JWT is granted access to specific Application and has a limited lifetime that is configured by you. However, best practice is to generate JWT for the shortest amount of time feasible for your application.
Here is an example of how to generate a JWT:

```ruby
require 'virgil/crypto'
require 'virgil/jwt'
include Virgil::Crypto
include Virgil::Jwt

# API_KEY (you got this Key at Virgil Dashboard)
api_key_base64 = "MC4CAQAwBQYDK2VwBCIEID8cTZz/sz2/iQ7mOndqwVpVazM8cUmjF49pPBqlqX3l"
private_key_data = Bytes.from_string(api_key_base64, VirgilStringEncoding::BASE64)

# Crypto library imports a private key into a necessary format
crypto = VirgilCrypto.new
api_key = crypto.import_private_key(private_key_data, "")

#  initialize accessTokenSigner that signs users JWTs
access_token_signer = VirgilAccessTokenSigner.new

# use your App Credentials you got at Virgil Dashboard:
app_id = "be00e10e4e1f4bf58f9b4dc85d79c77a" # APP_ID
api_key_id = "70b447e321f3a0fd"; # API_KEY_ID
ttl = 1*60 # 1 hour (JWT's lifetime in minutes)

# setup JWT generator with necessary parameters:
jwt_generator = JwtGenerator.new(app_id: app_id, 
                                 api_key: api_key, 
                                 api_public_key_id: api_key_id, 
                                 life_time: ttl, 
                                 access_token_signer: access_token_signer)

# generate JWT for a user
# remember that you must provide each user with his unique JWT
# each JWT contains unique user's identity (in this case - Alice)
# identity can be any value: name, email, some id etc.
identity = "Alice"
alice_jwt = jwt_generator.generate_token(identity)

# as result you get users JWT, it looks like this: "eyJraWQiOiI3MGI0NDdlMzIxZjNhMGZkIiwidHlwIjoiSldUIiwiYWxnIjoiVkVEUzUxMiIsImN0eSI6InZpcmdpbC1qd3Q7dj0xIn0.eyJleHAiOjE1MTg2OTg5MTcsImlzcyI6InZpcmdpbC1iZTAwZTEwZTRlMWY0YmY1OGY5YjRkYzg1ZDc5Yzc3YSIsInN1YiI6ImlkZW50aXR5LUFsaWNlIiwiaWF0IjoxNTE4NjEyNTE3fQ.MFEwDQYJYIZIAWUDBAIDBQAEQP4Yo3yjmt8WWJ5mqs3Yrqc_VzG6nBtrW2KIjP-kxiIJL_7Wv0pqty7PDbDoGhkX8CJa6UOdyn3rBWRvMK7p7Ak"
# you can provide users with JWT at registration or authorization steps
# Send a JWT to client-side
jwt_string = alice_jwt.to_s
puts(jwt_string)
```

### Manage a JWT

Each JWT consists of three parts: the `header`, the `payload`, and the `signature`.

```ruby
# JWT Token structure
header.payload.signature
```
#### Header

The header contains information about how the JWT signature should be computed. The header is a JSON object in the following format:
```ruby
{
  # the type of token. It MUST be "JWT"
  "typ": "JWT",
  # Signature algorithm. Currently supports only "VEDS512" (Virgil EdDSA SHA512)
  "alg": "VEDS512",
  # the content-type. It MUST be "virgil-jwt;v=1
  "cty": "virgil-jwt;v=1",
  # fingerprint of public key, that will be used to verify token. Equals to first 8 bytes of SHA512 of Public Key in DER format
  "kid": "70b447e321f3a0fd"
}
```

#### Payload

The payload is the data that‘s stored inside the JWT (this data is also referred to as the “claims” of the JWT). In our example, the Application server creates a JWT with the user information stored inside of it.
```ruby
{
  # Issuer. Equals to virgil-
  "iss": "virgil-be00e10e4e1f4bf58f9b4dc85d79c77a",
  # Subject. Equals to identity-
  "sub": "identity-Alice",
  # Issued at. Utc timestamp that indicates when token was issued.
  "iat": 1518612517,
  # Expires at. Utc timestamp that shows when token will expire. Tokens have a maximum age of 24 hours
  "exp": 1518698917
}
```
Keep in mind that the size of the data will affect the overall size of the JWT. This generally isn’t an issue but having excessively large JWT may negatively affect performance and cause latency.

#### Signature

The signature section is a signed hash that serves to prove the authenticity of the token. It is compiled by hashing the JWT header and payload together with your API Key secret, which should only be known to your application and Virgil.
The signature is computed using the following pseudo code:
```ruby
# Signature
signature = Base64.urlsafe_encode64(EdDSA+SHA512(SHA512(Base64.urlsafe_encode64(header) + "." + Base64.urlsafe_encode64(payload))))
```
Base64.urlsafe_encode64 encodes the header and the payload that was created in steps 1 and 2. The algorithm then joins the resulting encoded strings together with a period `(.)` in between them. To get the JWT signature, the data string is hashed with the secret key using the hashing algorithm specified in the JWT header.
Then, using the joined encoded header and payload and applying the specified signature algorithm(HS256) on the data string with the secret key set as the string “secret”, we get the JWT Signature.
Now that we have created all three components, we can create the JWT. Remembering the header.payload.signature structure of the JWT, we simply need to combine the components with periods `(.)` separating them. We use the Base64.urlsafe_encode64 encoded versions of the `header` and of the `payload`, and the `signature`.

Here is an example of JWT:

```ruby
# JWT Token
eyJraWQiOiI3MGI0NDdlMzIxZjNhMGZkIiwidHlwIjoiSldUIiwiYWxnIjoiVkVEUzUxMiIsImN0eSI6InZpcmdpbC1qd3Q7dj0xIn0.eyJleHAiOjE1MTg2OTg5MTcsImlzcyI6InZpcmdpbC1iZTAwZTEwZTRlMWY0YmY1OGY5YjRkYzg1ZDc5Yzc3YSIsInN1YiI6ImlkZW50aXR5LUFsaWNlIiwiaWF0IjoxNTE4NjEyNTE3fQ.MFEwDQYJYIZIAWUDBAIDBQAEQP4Yo3yjmt8WWJ5mqs3Yrqc_VzG6nBtrW2KIjP-kxiIJL_7Wv0pqty7PDbDoGhkX8CJa6UOdyn3rBWRvMK7p7Ak
```

It is important to understand that the purpose of using JWT is NOT to hide or obscure data in any way. The reason why JWT is used is to prove that the sent data was actually created by an authentic source.
You can try creating your own JWT through your browser at [jwt.io](https://jwt.io).

## Docs
- [Crypto Core Library](https://github.com/VirgilSecurity/virgil-crypto)

## License

This library is released under the [3-clause BSD License](https://github.com/VirgilSecurity/virgil-sdk-javascript/blob/master/LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
