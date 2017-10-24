# Authenticated Data Encryption

This guide is a short tutorial on how to sign then encrypt data with Virgil Security.

This process is called **Authenticated Data Encryption**. It is a form of encryption which simultaneously provides confidentiality, integrity, and authenticity assurances on the encrypted data. During this procedure you will sign then encrypt data using Alice’s **Virgil Key**, and then Bob’s **Virgil Card**. In order to do this, Alice’s Virgil Key must be loaded from the appropriate storage location, then Bob’s Virgil Card must be searched for, followed by preparation of the data for transmission, which is finally signed and encrypted before being sent.



Set up your project environment before you begin to work, with the [getting started](https://github.com/VirgilSecurity/virgil-sdk-ruby/blob/docs-review/documentation/guides/configuration/client-configuration.md) guide.

The Authenticated Data Encryption procedure is shown in the figure below.

![Authenticated Data Encryption](https://github.com/VirgilSecurity/virgil-sdk-ruby/blob/docs-review/documentation/img/Guides_introduction.png "Authenticated Data Encryption")

In order to **sign"** and **encrypt** a **message**, Alice has to have:
 - Her Virgil Key
 - Bob's Virgil Card

Let's review how to sign and encrypt data:

1. Developers need to initialize the **Virgil SDK**:

```ruby
virgil = VirgilApi.new(access_token: "[YOUR_ACCESS_TOKEN_HERE]")
```

2. Alice has to:

  - Load her Virgil Key from secure storage defined by default;
  - Search for Bob's Virgil Cards on **Virgil Services**;
  - Prepare a message for signature and encryption;
  - Encrypt and sign the message for Bob.

  ```ruby
  # load a Virgil Key from device storage
  alice_key = virgil.keys.load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")

  # search for Virgil Cards
  bob_cards = await virgil.cards.find("bob")

  # prepare the message
  message = "Hey Bob, how's it going?"

  # sign then encrypt the message
  ciphertext = alice_key.sign_then_encrypt(message, bob_cards).to_base64
  ```

To load a Virgil Key from a specific storage, developers need to change the storage path during Virgil SDK initialization.

In many cases you need receiver's Virgil Cards. See [Finding Cards](https://github.com/VirgilSecurity/virgil-sdk-ruby/blob/docs-review/documentation/guides/virgil-card/finding-card.md) guide to find them.
