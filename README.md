# Virgil Security Ruby SDK 

[Installation](#installation) | [Encryption Example](#encryption-example) | [Initialization](#initialization) | [Documentation](#documentation) | [Support](#support)

[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communication, securely store data, provide passwordless login, and ensure data integrity.

For a full overview head over to our Ruby [Get Started][_getstarted] guides.

## Installation

The Virgil SDK is provided as a gem named *virgil-sdk*. The package is distributed via *bundler* package manager.

The gem is available for Ruby 2.1 and newer.

Installing the gem

To install package use the command below:

```
gem install virgil-sdk
```

or add the following line to your Gemfile:

```
gem 'virgil-sdk', '~> 4.2.5'
```

__Next:__ [Get Started with the Ruby SDK][_getstarted].

## Encryption Example

Virgil Security makes it super easy to add encryption to any application. With our SDK you create a public [__Virgil Card__][_guide_virgil_cards] for every one of your users and devices. With these in place you can easily encrypt any data in the client.

```ruby
require "virgil/sdk"
include Virgil::SDK::HighLevel

# initialize Virgil SDK
virgil = VirgilApi.new(access_token: "[YOUR_ACCESS_TOKEN_HERE]")

# find Alice's card(s)
alice_cards = virgil.cards.find("alice")

# encrypt the message using Alice's cards
message = "Hello Alice!"
encrypted_message = alice_cards.encrypt(message)

# transmit the message with your preferred technology
 transmit_message(encrypted_message.to_base64)
```

The receiving user then uses their stored __private key__ to decrypt the message.


```ruby
# load Alice's Key from storage.
alice_key = virgil.keys.load("alice_key_1", "mypassword")

# decrypt the message using the key 
original_message = alice_key.decrypt(transfer_data).to_s
```

__Next:__ To [get you properly started][_guide_encryption] you'll need to know how to create and store Virgil Cards. Our [Get Started guide][_guide_encryption] will get you there all the way.

__Also:__ [Encrypted communication][_getstarted_encryption] is just one of the few things our SDK can do. Have a look at our guides on  [Encrypted Storage][_getstarted_storage], [Data Integrity][_getstarted_data_integrity] and [Passwordless Login][_getstarted_passwordless_login] for more information.


## Initialization

To use this SDK you need to [sign up for an account](https://developer.virgilsecurity.com/account/signup) and create your first __application__. Make sure to save the __app id__, __private key__ and it's __password__. After this, create an __application token__ for your application to make authenticated requests from your clients.

To initialize the SDK on the client side you will only need the __access token__ you created.

```ruby
virgil = VirgilApi.new(access_token: "[YOUR_ACCESS_TOKEN_HERE]")
```

> __Note:__ this client will have limited capabilities. For example, it will be able to generate new __Cards__ but it will need a server-side client to transmit these to Virgil.

To initialize the SDK on the server side we will need the __access token__, __app id__ and the __App Key__ you created on the [Developer Dashboard](https://developer.virgilsecurity.com/).

```ruby
 # initialize Virgil SDK high-level instance.
context = VirgilContext.new(
    access_token: "[YOUR_ACCESS_TOKEN_HERE]",
    # Credentials are required only in case of publish and revoke local Virgil Cards.
    credentials: VirgilAppCredentials.new(app_id: "[YOUR_APP_ID_HERE]",
                                        app_key_data: VirgilBuffer.from_file("[YOUR_APP_KEY_PATH_HERE]"),
                                        app_key_password: "[YOUR_APP_KEY_PASSWORD_HERE]")
                                        )

virgil = VirgilApi.new(context: context)

```

Next: [Learn more about our the different ways of initializing the Ruby SDK][_guide_initialization] in our documentation.

## Documentation

Virgil Security has a powerful set of APIs, and the documentation is there to get you started today.

* [Get Started][_getstarted_root] documentation
  * [Initialize the SDK][_initialize_root]
  * [Encrypted storage][_getstarted_storage]
  * [Encrypted communication][_getstarted_encryption]
  * [Data integrity][_getstarted_data_integrity]
  * [Passwordless login][_getstarted_passwordless_login]
* [Guides][_guides]
  * [Virgil Cards][_guide_virgil_cards]
  * [Virgil Keys][_guide_virgil_keys]

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support

Our developer support team is here to help you. You can find us on [Twitter](https://twitter.com/virgilsecurity) and [email](support).

[support]: mailto:support@virgilsecurity.com
[_getstarted_root]: https://virgilsecurity.com/docs/sdk/ruby/
[_getstarted]: https://virgilsecurity.com/docs/sdk/ruby/
[_getstarted_encryption]: https://virgilsecurity.com/docs/use-cases/encrypted-communication
[_getstarted_storage]: https://virgilsecurity.com/docs/use-cases/secure-data-at-rest
[_getstarted_data_integrity]: https://virgilsecurity.com/docs/use-cases/data-verification
[_getstarted_passwordless_login]: https://virgilsecurity.com/docs/use-cases/passwordless-authentication
[_guides]: https://virgilsecurity.com/docs/sdk/ruby/features
[_guide_initialization]: https://virgilsecurity.com/docs/sdk/ruby/getting-started#initializing
[_guide_virgil_cards]: https://virgilsecurity.com/docs/sdk/ruby/features#virgil-cards
[_guide_virgil_keys]: https://virgilsecurity.com/docs/sdk/ruby/features#virgil-keys
[_guide_encryption]: https://virgilsecurity.com/docs/sdk/ruby/features#encryption
[_initialize_root]: https://virgilsecurity.com/docs/sdk/ruby/programming-guide#initializing
