# Ruby SDK Programming Guide

This guide is a practical introduction to creating Ruby apps using Virgil Security features. The code examples in this guide are written in Ruby.

In this guide you will find code for every task you need to implement in order to create an application using Virgil Security. It also includes a description of the main classes and methods. The aim of this guide is to get you up and running quickly. You should be able to copy and paste the code provided into your own apps and use it with minumal changes.

## Table of Contents

* [Setting up your project](#setting-up-your-project)
* [User and App Credentials](#user-and-app-credentials)
* [Creating a Virgil Card](#creating-a-virgil-card)
* [Search for Virgil Cards](#search-for-virgil-cards)
* [Getting a Virgil Card](#getting-a-virgil-card)
* [Validating Virgil Cards](#validating-virgil-cards)
* [Revoking a Virgil Card](#revoking-a-virgil-card)
* [Operations with Crypto Keys](#operations-with-crypto-keys)
  * [Generate Keys](#generate-keys)
  * [Import and Export Keys](#import-and-export-keys)
* [Encryption and Decryption](#encryption-and-decryption)
  * [Encrypt Data](#encrypt-data)
  * [Decrypt Data](#decrypt-data)
* [Generating and Verifying Signatures](#generating-and-verifying-signatures)
  * [Generating a Signature](#generating-a-signature)
  * [Verifying a Signature](#verifying-a-signature)
* [Authenticated Encryption](#authenticated-encryption)
  * [Sign then Encrypt](#sign-then-encrypt)
  * [Decrypt then Verify](#decrypt-then-verify)
* [Fingerprint Generation](#fingerprint-generation)
* [Release Notes](#release-notes)

## Setting up your project

The Virgil SDK is provided as a gem named *virgil-sdk*. The package is distributed via *bundler* package manager.

### Target platforms

* Ruby 2.0+

### Installation

To install package use the command below:

```
gem install virgil-sdk --pre
```

or add the following line to your Gemfile:

```
gem 'virgil-sdk', '~> 4.0.0b'
```

## User and App Credentials

When you register an application on the Virgil developer's [dashboard](https://developer.virgilsecurity.com/dashboard), we provide you with an *app_id*, *app_key* and *access_token*.

* **app_id** uniquely identifies your application in our services, it is also used to identify the Public key generated in a pair with *app_key*, for example: ```af6799a2f26376731abb9abf32b5f2ac0933013f42628498adb6b12702df1a87```
* **app_key** is a Private key that is used to perform creation and revocation of *Virgil Cards* (Public key) in Virgil services. Also the *app_key* can be used for cryptographic operations to take part in application logic. The *app_key* is generated at the time of creation application and has to be saved in secure place. 
* **access_token** is a unique string value that provides an authenticated secure access to the Virgil services and is passed with each API call. The *accessToken* also allows the API to associate your app’s requests with your Virgil developer’s account. 

## Connecting to Virgil
Before you can use any Virgil services features in your app, you must first initialize ```VirgilClient``` class from ```Virgil::SDK::Client``` module. You use the ```VirgilClient``` object to get access to Create, Revoke and Search for *Virgil Cards* (Public keys). 

### Initializing an API Client

To create an instance of *VirgilClient* class, just call its constructor with your application's *access_token* which you generated on developer's deshboard.

Module: ```Virgil::SDK::Client```

```ruby
require 'virgil/sdk'

client = Virgil::SDK::Client::VirgilClient.new("[YOUR_ACCESS_TOKEN_HERE]")
```

you can also customize initialization using your own parameters

```ruby
client = Virgil::SDK::Client::VirgilClient.new(
    "[YOUR_ACCESS_TOKEN_HERE]",
    https://cards.virgilsecurity.com",
    https://cards-ro.virgilsecurity.com"
)
```

### Initializing Crypto

The *VirgilCrypto* class provides cryptographic operations in applications, such as hashing, signature generation and verification, and encryption and decryption.

Module: ```Virgil::SDK::Cryptography```

```ruby
require 'virgil/sdk'

crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
```

## Creating a Virgil Card

A *Virgil Card* is the main entity of the Virgil services, it includes the information about the user and his public key. The *Virgil Card* identifies the user/device by one of his types.

Collect an *app_id* and *app_key* for your app. These parametes are required to create a Virgil Card in your app scope.

```ruby
app_id = "[YOUR_APP_ID_HERE]"
app_key_password = "[YOUR_APP_KEY_PASSWORD_HERE]"
app_key_data = Virgil::Crypto::Bytes.from_string(File.read("[YOUR_APP_KEY_PATH_HERE]"))

app_key = crypto.import_private_key(app_key_data, app_key_password)
```
Generate a new Public/Private keypair using *VirgilCrypto* class.

```ruby
alice_keys = crypto.generate_keys()
```

Prepare request

```ruby
exported_public_key = crypto.export_public_key(alice_keys.public_key)
create_card_request = Virgil::SDK::Client::Requests::CreateCardRequest.new(
  identity: "alice",
  identity_type: "username",
  public_key: exported_public_key
)
```

then, use *RequestSigner* class to sign request with owner and app keys.

```ruby
request_signer = Virgil::SDK::Client::RequestSigner.new(crypto)

request_signer.self_sign(create_card_request, alice_keys.private_key)
requestSigner.authority_sign(create_card_request, app_id, app_key)
```
Publish a Virgil Card

```ruby
alice_card = client.create_card_from_signed_request(create_card_request)
```

Or you can use the shorthand versions

```ruby
alice_keys = crypto.generate_keys

alice_card = virgil_client.create_card(
  "alice",
  "username",
  alice_keys,
  app_id,
  app_key
)
```

this will sign and send the card creation request.

## Search for Virgil Cards

Performs the `Virgil Card`s search by criteria:
- the *identities* request parameter is mandatory;
- the *identity_type* is optional and specifies the *IdentityType* of a `Virgil Card`s to be found;
- the *scope* optional request parameter specifies the scope to perform search on. Either 'global' or 'application'. The default value is 'application';

```ruby
client = Virgil::SDK::Client::VirgilClient.new("[YOUR_ACCESS_TOKEN_HERE]")

criteria = Virgil::SDK::Client::SearchCriteria.by_identities("alice", "bob")
cards = client.search_cards_by_criteria(criteria)
```

Or you can use the shorthand versions
```ruby
client = Virgil::SDK::Client::VirgilClient.new("[YOUR_ACCESS_TOKEN_HERE]")

cards = client.search_cards_by_identities("alice", "bob")
app_bundle_cards = client.seach_cards_by_app_bundle("[APP_BUNDLE]")
```

## Getting a Virgil Card

Gets a `Virgil Card` by ID.

```ruby
client = Virgil::SDK::Client::VirgilClient.new("[YOUR_ACCESS_TOKEN_HERE]")
card = client.get_card("[YOUR_CARD_ID_HERE]")
```

## Validating Virgil Cards

This sample uses *built-in* ```CardValidator``` to validate cards. By default ```CardValidator``` validates only *Cards Service* signature.

```ruby
# Initialize crypto API
crypto = Virgil::SDK::Cryptography::VirgilCrypto.new

validator = Virgil::SDK::Client::CardValidator.new(crypto)

# Your can also add another Public Key for verification.
# validator.add_verifier("[HERE_VERIFIER_CARD_ID]", [HERE_VERIFIER_PUBLIC_KEY]);

# Initialize service client
client = Virgil::SDK::Client::VirgilClient.new("[YOUR_ACCESS_TOKEN_HERE]")
client.set_card_validator(validator)

begin
    cards = client.search_cards_by_identities("alice", "bob");
rescue Virgil::SDK::Client::InvalidCardException => ex
    # ex.invalid_cards is the list of Card objects that didn't pass validation
end
```

## Revoking a Virgil Card

Initialize required components.

```ruby
client = Virgil::SDK::Client::VirgilClient.new("[YOUR_ACCESS_TOKEN_HERE]")
crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
request_signer = Virgil::SDK::Client::RequestSigner.new(crypto)
```

Collect *App* credentials

```ruby
app_id = "[YOUR_APP_ID_HERE]"
app_key_password = "[YOUR_APP_KEY_PASSWORD_HERE]"
app_key_path = "[YOUR_APP_KEY_PATH_HERE]"
app_key_data = Virgil::Crypto::Bytes.from_string(File.read(app_key_path))

app_key = crypto.import_private_key(app_key_data, app_key_password)
```

Prepare revocation request

```ruby
card_id = "[YOUR_CARD_ID_HERE]"

revoke_request = Virgil::SDK::Client::Requests::RevokeCardRequest(
  card_id, Virgil::SDK::Client::Requests::RevokeCardRequest::Reasons::Unspecified
)
request_signer.authority_sign(revoke_request, app_id, app_key)

client.revoke_card_from_signed_request(revoke_request)
```

The shorthand version is

```ruby
client.revoke_card(
  "[YOUR_CARD_ID_HERE]",
  Virgil::SDK::Client::Requests::RevokeCardRequest::Reasons::Unspecified,
  app_id,
  app_key
)
```
## Adding card relation
Create request
```ruby
add_relation_request = Virgil::SDK::Client::Requests::AddRelationRequest.new(
  trusted_card
)
```
sign request with trustor card
```ruby
request_signer = Virgil::SDK::Client::RequestSigner.new(crypto)

request_signer.authority_sign(add_relation_request, alice_card.id, alice_key.private_key)
 
 ```
 
publish request
```ruby
 client.add_relation(add_relation_request)
 ```
 
## Deleting card relation
Create request
```ruby
delete_relation_request = Virgil::SDK::Client::Requests::DeleteRelationRequest.new(
  trusted_card.id
)
```
sign request with trustor card
```ruby
request_signer = Virgil::SDK::Client::RequestSigner.new(crypto)

request_signer.authority_sign(delete_relation_request, alice_card.id, alice_key.private_key)
 
 ```
 
publish request
```ruby
 client.delete_relation(delete_relation_request)
 ```

## Operations with Crypto Keys

### Generate Keys
The following code sample illustrates keypair generation. The default algorithm is ed25519

```ruby
alice_keys = crypto.generate_keys
```

### Import and Export Keys
You can export and import your Public/Private keys to/from supported wire representation.

To export Public/Private keys, simply call one of the Export methods:

```ruby
exported_private_key = crypto.export_private_key(alice_keys.private_key)
exported_public_key = crypto.export_public_key(alice_keys.public_key)
```

To import Public/Private keys, simply call one of the Import methods:

```ruby
private_key = crypto.import_private_key(exported_private_key)
public_key = crypto.import_public_key(exported_public_key)
```

## Encryption and Decryption

Initialize Crypto API and generate keypair.

```ruby
crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
alice_keys = crypto.generate_keys
```

### Encrypt Data

Data encryption using ECIES scheme with AES-GCM.
There can be more than one recipient.

```ruby
plain_data = Virgil::Crypto::Bytes.from_string("Hello Bob!")
cipher_data = crypto.encrypt(plain_data, alice_keys.public_key)
```

### Decrypt Data

You can decrypt data using your private key

```ruby
crypto.decrypt(cipher_data, alice_keys.private_key);
```

## Generating and Verifying Signatures

This section walks you through the steps necessary to use the
*VirgilCrypto* to generate a digital signature for data
and to verify that a signature is authentic.

Generate a new Public/Private keypair and *data* to be signed.

```ruby
crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
alice_keys = crypto.generate_keys()

# The data to be signed with alice's Private key
data = Virgil::Crypto::Bytes.from_string("Hello Bob, How are you?")
```

### Generating a Signature

Sign the SHA-384 fingerprint of bytes using your private key.
To generate the signature, simply call the sign method:

```ruby
signature = crypto.sign(data, alice.private_key)
```

### Verifying a Signature

Verify the signature of the SHA-384 fingerprint of bytes using Public key.
The signature can now be verified by calling the verify method:

```ruby
is_valid = crypto.verify(data, signature, alice.public_key)
```

## Authenticated Encryption
Authenticated Encryption provides both data confidentiality and data
integrity assurances to the information being protected.

```ruby
crypto = Virgil::SDK::Cryptography::VirgilCrypto.new

alice = crypto.generate_keys
bob = crypto.generate_keys

# The data to be signed with alice's Private key
data = Virgil::Crypto::Bytes.from_string("Hello Bob, How are you?")
```

### Sign then Encrypt

```ruby
cipher_data = crypto.sign_then_encrypt(
  data,
  alice.private_key,
  bob.public_key
)
```

### Decrypt then Verify
```ruby
decrypted_data = crypto.decrypt_then_verify(
  cipher_data,
  bob.private_key,
  alice.public_key
)
```

## Fingerprint Generation

The default Fingerprint algorithm is SHA-256.

```ruby
crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
fingerprint = crypto.calculate_fingerprint(content_bytes)
```

## Release Notes
 - Please read the latest note here: [https://github.com/VirgilSecurity/virgil-sdk-ruby/releases](https://github.com/VirgilSecurity/virgil-sdk-ruby/releases)
