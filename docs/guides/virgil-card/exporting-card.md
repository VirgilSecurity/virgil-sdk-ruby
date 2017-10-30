# Exporting Card

This guide shows how to export a **Virgil Card** to the string representation.

Set up your project environment before you begin to export a Virgil Card, with the [getting started](/documentation/guides/configuration/client-configuration.md) guide.

In order to export a Virgil Card, we need to:

- Initialize the **Virgil SDK**

```ruby
virgil = VirgilApi.new(access_token: "[YOUR_ACCESS_TOKEN_HERE]")
```

- Use the code below to export the Virgil Card to its string representation.

```ruby
# export a Virgil Card to string
exported_alice_card = alice_card.export
```

The same mechanism works for **Global Virgil Card**.
