# Importing Virgil Key

This guide shows how to export a **Virgil Key** from a Base64 encoded string representation.

Set up your project environment before you begin to import a Virgil Key, with the [getting started](https://github.com/VirgilSecurity/virgil-sdk-ruby/blob/docs-review/documentation/guides/configuration/client-configuration.md) guide.

In order to import a Virgil Key, we need to:

- Initialize **Virgil SDK**

```ruby
virgil = VirgilApi.new(access_token: "[YOUR_ACCESS_TOKEN_HERE]")
```

- Choose a Base64 encoded string
- Import the Virgil Key from the Base64 encoded string

```ruby
# initialize a buffer from base64 encoded string
alice_key_buffer = VirgilBuffer.from_base64("[BASE64_ENCODED_VIRGIL_KEY]")

# import Virgil Key from buffer
alice_key = virgil.keys.import(alice_key_buffer, "[OPTIONAL_KEY_PASSWORD]")
```
