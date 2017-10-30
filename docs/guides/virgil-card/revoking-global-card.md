# Revoking Global Card

This guide shows how to revoke a **Global Virgil Card**.

Set up your project environment before you begin to revoke a Global Virgil Card, with the [getting started](/documentation/guides/configuration/client-configuration.md) guide.

In order to revoke a Global Virgil Card, we need to:

-  Initialize the Virgil SDK

```ruby
virgil = VirgilApi.new(context: VirgilContext.new(
    access_token: "[YOUR_ACCESS_TOKEN_HERE]",
    credentials: VirgilAppCredentials.new(
        app_id: "[YOUR_APP_ID_HERE]",
        app_key_data: VirgilBuffer.from_file("[YOUR_APP_KEY_PATH_HERE]"),
        app_key_password: "[YOUR_APP_KEY_PASSWORD_HERE]"))
)
```

- Load Alice's **Virgil Key** from the secure storage provided by default
- Load Alice's Virgil Card from **Virgil Services**
- Initiate the Card's identity verification process
- Confirm the Card's identity using a **confirmation code**
- Revoke the Global Virgil Card from Virgil Services

```ruby
# load a Virgil Key from storage
alice_key = virgil.keys.load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")

# load a Virgil Card from Virgil Services
alice_card = virgil.cards.get("[USER_CARD_ID_HERE]")

# initiate an identity verification process.
attempt = alice_card.check_identity()

# grab a validation token
token = attempt.confirm(VirgilIdentity::EmailConfirmation
.new("[CONFIRMATION_CODE]"))

# revoke a Global Virgil Card
virgil.cards.revoke_global(alice_card, alice_key, token)
```
