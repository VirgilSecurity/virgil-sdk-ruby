# Virgil Security Ruby SDK
[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-sdk-ruby.svg?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-sdk-ruby)
[![Gem](https://img.shields.io/gem/v/virgil-sdk.svg)](https://github.com/VirgilSecurity/virgil-sdk-ruby)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)
[![Documentation YARD](https://img.shields.io/badge/docs-yard-blue.svg)](https://virgilsecurity.github.io/virgil-sdk-ruby)

[SDK Features](#sdk-features) | [Installation](#installation) | [Initialization](#initialization) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

<img width="230px" src="logo.png" align="left" hspace="10" vspace="6"> [Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communication, securely store data, provide passwordless login, and ensure data integrity.

The Virgil SDK allows developers to get up and running with Virgil API quickly and add full end-to-end security to their existing digital solutions to become HIPAA and GDPR compliant and more.

## SDK Features
- Communicate with Virgil Cards Service
- Manage users' public keys
- Encrypt, sign, decrypt and verify data
- Store private keys in secure local storage
- Use Virgil Crypto Library
- Use your own crypto library


## Installation

The Virgil SDK is provided as a gem named *virgil-sdk* and available for Ruby 2.1 and newer. The package is distributed via *bundler* package manager.

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

Virgil Security has a powerful set of APIs, and the [Developer Documentation](https://developer.virgilsecurity.com/) can get you started today.

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support

Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).


[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-crypto


