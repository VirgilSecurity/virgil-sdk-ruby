# Client Configuration

In order to use the Virgil Infrastructure, set up your client and implement the required mechanisms using the following guide.


## Install SDK

The Virgil Ruby SDK is provided as a package named virgil-sdk. The package is distributed via bundler package manager.

The package is available for Ruby 2.1 and newer.

Installing the package:

To install the gem use the command below:
```ruby
gem install virgil-sdk
```
or add the following line to your Gemfile:
```ruby
gem 'virgil-sdk', '~> 4.2.6'
```

## Obtain an Access Token
When users want to start sending and receiving messages on computer or mobile device, Virgil can't trust them right away. Clients have to be provided with a unique identity, thus, you'll need to give your users the Access Token that tells Virgil who they are and what they can do.

Each your client must send to you the Access Token request with their registration request. Then, your service that will be responsible for handling access requests must handle them in case of users successful registration on your Application server.

```
// an example of an Access Token representation
AT.7652ee415726a1f43c7206e4b4bc67ac935b53781f5b43a92540e8aae5381b14
```

## Initialize SDK

### With a Token
With Access Token, we can initialize the Virgil PFS SDK on the client side to start doing fun stuff like sending and receiving messages. To initialize the **Virgil SDK** on the client side, you need to use the following code:

#{ import "/guides/configuration/client/__code__/%lang%#initialize_with_token" }

### Without a Token

In case of a **Global Virgil Card** creation you don't need to initialize the SDK with the Access Token. For more information about the Global Virgil Card creation check out the [Creating Global Card guide](/docs/guides/virgil-card/creating-global-card.md).

Use the following code to initialize Virgil SDK without Access Token.

#{ import "/guides/configuration/client/__code__/%lang%#initialize_without_token" }
