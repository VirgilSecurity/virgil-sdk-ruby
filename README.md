# Virgil Security Ruby SDK
[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-sdk-ruby.svg?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-sdk-ruby)
[![Gem](https://img.shields.io/gem/v/virgil-sdk.svg)](https://rubygems.org/gems/virgil-sdk)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)
[![Documentation YARD](https://img.shields.io/badge/docs-yard-blue.svg)](https://virgilsecurity.github.io/virgil-sdk-ruby)

[SDK Features](#sdk-features) | [Installation](#installation) | [Initialization](#initialization) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

<img width="230px" src="logo.png" align="left" hspace="10" vspace="6"> [Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communication, securely store data, provide passwordless login, and ensure data integrity.

The Virgil SDK allows developers to get up and running with Virgil API quickly and add full end-to-end security to their existing digital solutions to become HIPAA and GDPR compliant and more.

## SDK Features
- communicate with [Virgil Cards Service][_cards_service]
- manage users' Public Keys
- store private keys in secure local storage
- use Virgil [Crypto library][_virgil_crypto]

## Installation

The Virgil SDK is provided as a [gem](https://rubygems.org/) named [*virgil-sdk*](https://rubygems.org/gems/virgil-sdk) and available for Ruby 2.1 and newer. The package is distributed via *bundler* package manager.

To install the package use the command below:

```
gem install virgil-sdk
```

or add the following line to your Gemfile:

```
gem 'virgil-sdk', '~> 4.4'
```


## Initialization

Be sure that you have already registered at the [Dev Portal](https://developer.virgilsecurity.com/account/signin) and created your application.

To initialize the SDK at the __Client Side__ you need only the __Access Token__ created for a client at Dev Portal. The Access Token helps to authenticate client's requests.

```ruby
virgil = VirgilApi.new(access_token: "[YOUR_ACCESS_TOKEN_HERE]")
```

To initialize the SDK at the __Server Side__ you need the application credentials (__Access Token__, __App ID__, __App Key__ and __App Key Password__) you got during Application registration at the Dev Portal.

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


## Usage Examples

#### Generate and publish user's Cards with Public Keys inside on Cards Service
Use the following lines of code to create and publish a user's Card with Public Key inside on Virgil Cards Service:

```Ruby
# generate a new Virgil Key
alice_key = virgil.keys.generate()

# save the Virgil Key into a storage
alice_key.save("[KEY_NAME]", "[KEY_PASSWORD]")

# create a Virgil Card
alice_card = virgil.cards.create("alice", alice_key)

# export the Virgil Card to a string
exported_alice_card = alice_card.export

# transmit the Card to your App Server
# import the Virgil Card from the string
alice_card = virgil.cards.import(exported_alice_card)

# publish the Virgil Card on the Virgil Cards Service
virgil.cards.publish(alice_card)
```

#### Sign then encrypt data

Virgil SDK lets you use a user's Private key and his or her Cards to sign, then encrypt any kind of data.

In the following example, we load a Private Key from a customized Key Storage and get recipient's Card from the Virgil Cards Services. Recipient's Card contains a Public Key on which we will encrypt the data and verify a signature.

```ruby
# load a Virgil Key from a device storage
alice_key = virgil.keys.load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")

# search for Virgil Cards
bob_cards = await virgil.cards.find("bob")

# prepare a message
message = "Hey Bob, how's it going?"

# sign then encrypt the message
ciphertext = alice_key.sign_then_encrypt(message, bob_cards).to_base64
```

#### Decrypt then verify data
Once the Users receive the signed and encrypted message, they can decrypt it with their own Private Key and verify signature with a Sender's Card:

```Ruby
# load a Virgil Key from a device storage
bob_key = virgil.keys.load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")

# get a sender's Virgil Card
alice_card = virgil.cards.get("[ALICE_CARD_ID]")

# decrypt the message
original_message = bob_key.decrypt_then_verify(ciphertext, alice_card).to_s
```

## Docs
Virgil Security has a powerful set of APIs, and the documentation below can get you started today.

In order to use the Virgil SDK with your application, you will need to first configure your application. By default, the SDK will attempt to look for Virgil-specific settings in your application but you can change it during SDK configuration.

* [Configure the SDK][_configure_sdk] documentation
  * [Setup authentication][_setup_authentication] to make API calls to Virgil Services
  * [Setup Card Manager][_card_manager] to manage user's Public Keys
  * [Setup Card Verifier][_card_verifier] to verify signatures inside of user's Card
  * [Setup Key storage][_key_storage] to store Private Keys
* [More usage examples][_more_examples]
  * [Create & publish a Card][_create_card] that has a Public Key on Virgil Cards Service
  * [Search user's Card by user's identity][_search_card]
  * [Get user's Card by its ID][_get_card]
  * [Use Card for crypto operations][_use_card]
* [Reference API][_reference_api]

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support

Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://join.slack.com/t/VirgilSecurity/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).


[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-crypto
[_cards_service]: https://developer.virgilsecurity.com/docs/api-reference/card-service/v4
[_use_card]: https://developer.virgilsecurity.com/docs/ruby/how-to/public-key-management/v4/use-card-for-crypto-operation
[_get_card]: https://developer.virgilsecurity.com/docs/ruby/how-to/public-key-management/v4/get-card
[_search_card]: https://developer.virgilsecurity.com/docs/ruby/how-to/public-key-management/v4/search-card
[_create_card]: https://developer.virgilsecurity.com/docs/ruby/how-to/public-key-management/v4/create-card
[_key_storage]: https://developer.virgilsecurity.com/docs/ruby/how-to/setup/v4/setup-key-storage
[_card_verifier]: https://developer.virgilsecurity.com/docs/ruby/how-to/setup/v4/setup-card-verifier
[_card_manager]: https://developer.virgilsecurity.com/docs/ruby/how-to/setup/v4/setup-card-manager
[_setup_authentication]: https://developer.virgilsecurity.com/docs/ruby/how-to/setup/v4/setup-authentication
[_services_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
[_configure_sdk]: https://developer.virgilsecurity.com/docs/how-to#sdk-configuration
[_more_examples]: https://developer.virgilsecurity.com/docs/how-to#public-key-management
[_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
