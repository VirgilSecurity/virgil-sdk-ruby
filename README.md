# Virgil Security Ruby SDK

[Installation](#installation) | [Initialization](#initialization) | [Encryption / Decryption Example](#encryption-example) |  [Documentation](#documentation) | [Reference API][_reference_api] | [Support](#support)

[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few steps, you can encrypt communication, securely store data, provide passwordless authentication, and ensure data integrity.

To initialize and use Virgil SDK, you need to have [Developer Account](https://developer.virgilsecurity.com/account/signin).

## Installation

The Virgil SDK is provided as a gem named *virgil-sdk* and available for Ruby 2.1 and newer. The package is distributed via *bundler* package manager.

To install the package use the command below:

```
gem install virgil-sdk
```

or add the following line to your Gemfile:

```
gem 'virgil-sdk', '~> 4.3'
```


## Initialization

Be sure that you have already registered at the [Dev Portal](https://developer.virgilsecurity.com/account/signin) and created your application.

To initialize the SDK at the __Client Side__ you need only the __Access Token__ created for a client at [Dev Portal](https://developer.virgilsecurity.com/account/signin). The Access Token helps to authenticate client's requests.

```ruby
virgil = VirgilApi.new(access_token: "[YOUR_ACCESS_TOKEN_HERE]")
```

To initialize the SDK at the __Server Side__ you need the application credentials (__Access Token__, __App ID__, __App Key__ and __App Key Password__) you got during Application registration at the [Dev Portal](https://developer.virgilsecurity.com/account/signin).

```ruby
 # initialize Virgil SDK high-level instance.
context = VirgilContext.new(
    access_token: "[YOUR_ACCESS_TOKEN_HERE]",
    # Credentials are required only to publish and revoke Virgil Cards.
    credentials: VirgilAppCredentials.new(
        app_id: "[YOUR_APP_ID_HERE]",
        app_key_data: VirgilBuffer.from_file("[YOUR_APP_KEY_PATH_HERE]"),
        app_key_password: "[YOUR_APP_KEY_PASSWORD_HERE]"))

virgil = VirgilApi.new(context: context)

```


## Encryption / Decryption Example

Virgil Security makes it super easy to add encryption to any application. With our SDK you create a public [__Virgil Card__][_guide_virgil_cards] for every one of your users and devices. With these in place you can easily encrypt any data in the client.

```ruby
require "virgil/sdk"
include Virgil::SDK::HighLevel

# initialize Virgil SDK
virgil = VirgilApi.new(access_token: "[YOUR_ACCESS_TOKEN_HERE]")

# find Alice's Virgil Card(s) at Virgil Services
alice_cards = virgil.cards.find("alice")

# encrypt the message using Alice's Virgil Cards
message = "Hello Alice!"
encrypted_message = alice_cards.encrypt(message)

# transmit the message with your preferred technology to Alice
 transmit_message(encrypted_message.to_base64)
```

Alice uses her Virgil Private Key to decrypt the encrypted message.


```ruby
# load Alice's Private Virgil Key from her local storage.
alice_key = virgil.keys.load("alice_key_1", "mypassword")

# decrypt the message using Alice's Private Virgil Key
original_message = alice_key.decrypt(transfer_data).to_s
```

__Next:__ On the page below you can find configuration documentation and the list of our guides and use cases where you can see appliance of Virgil Ruby SDK.


## Documentation

Virgil Security has a powerful set of APIs and the documentation to help you get started:

* [Get Started](/docs/get-started) documentation
  * [Encrypted storage](/docs/get-started/encrypted-storage.md)
  * [Encrypted communication](/docs/get-started/encrypted-communication.md)
  * [Data integrity](/docs/get-started/data-integrity.md)
* [Guides](/docs/guides)
  * [Virgil Cards](/docs/guides/virgil-card)
  * [Virgil Keys](/docs/guides/virgil-key)
  * [Encryption](/docs/guides/encryption)
  * [Signature](/docs/guides/signature)
* [Configuration](/docs/guides/configuration)
  * [Set Up Client Side](/docs/guides/configuration/client.md)
  * [Set Up Server Side](/docs/guides/configuration/server.md)

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support

Our developer support team is here to help you. You can find us on [Twitter](https://twitter.com/virgilsecurity) and [email][support].

[support]: mailto:support@virgilsecurity.com
