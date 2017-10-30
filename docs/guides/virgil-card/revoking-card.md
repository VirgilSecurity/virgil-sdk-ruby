# Revoking Card

This guide shows how to revoke a **Virgil Card** from Virgil Services.

Set up your project environment before you begin to revoke a Virgil Card, with the [getting started](/docs/guides/configuration/client-configuration.md) guide.

In order to revoke a Virgil Card, we need to:

- Initialize the **Virgil SDK** and enter Application **credentials** (**App ID**, **App Key**, **App Key password**)

```ruby
virgil = VirgilApi.new(context: VirgilContext.new(
    access_token: "[YOUR_ACCESS_TOKEN_HERE]",
    credentials: VirgilAppCredentials.new(
        app_id: "[YOUR_APP_ID_HERE]",
        app_key_data: VirgilBuffer.from_file("[YOUR_APP_KEY_PATH_HERE]"),
        app_key_password: "[YOUR_APP_KEY_PASSWORD_HERE]"))
)
```

- Get Alice's Virgil Card by **ID** from **Virgil Services**
- Revoke Alice's Virgil Card from Virgil Services

```ruby
# get a Virgil Card by ID
alice_card = virgil.cards.get("[USER_CARD_ID_HERE]")

# revoke a Virgil Card
virgil.cards.revoke(alice_card)
```
