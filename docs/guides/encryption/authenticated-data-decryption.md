# Authenticated Data Decryption

This guide is short tutorial on how to decrypt and then verify data with Virgil Security.

This process is called **Authenticated Data Decryption**. During this procedure you work with encrypted and signed data, decrypting and verifying them. A recipient uses their **Virgil Key** (to decrypt the data) and **Virgil Card** (to verify data integrity).


Set up your project environment before you begin to work, with the [getting started](/docs/guides/configuration/client-configuration.md) guide.

The Authenticated Data Decryption procedure is shown in the figure below.

![Virgil Intro](/docs/img/Guides_introduction.png "Authenticated Data Decryption")

In order to decrypt and verify the message, Bob has to have:
 - His Virgil Key
 - Alice's Virgil Card

Let's review how to decrypt and verify data:

1. Developers need to initialize the **Virgil SDK**

```ruby
virgil = VirgilApi.new(access_token: "[YOUR_ACCESS_TOKEN_HERE]")
```

2. Then Bob has to:

 - Load his own Virgil Key from secure storage, defined by default
 - Search for Alice's Virgil Card on **Virgil Services**
 - Decrypt the message using his Virgil Key and verify it using Alice's Virgil Card

 ```ruby
 # load a Virgil Key from device storage
 bob_key = virgil.keys.load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")

 # get a sender's Virgil Card
 alice_card = virgil.cards.get("[ALICE_CARD_ID]")

 # decrypt the message
 original_message = bob_key.decrypt_then_verify(ciphertext, alice_card).to_s
 ```

To load a Virgil Key from a specific storage, developers need to change the storage path during Virgil SDK initialization.

To decrypt data, you need Bob's stored Virgil Key. See the [Storing Keys](/docs/guides/virgil-key/saving-key.md) guide for more details.
