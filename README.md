# Virgil Security Ruby SDK
[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-sdk-ruby.svg?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-sdk-ruby)
[![Gem](https://img.shields.io/gem/v/virgil-sdk.svg)](https://rubygems.org/gems/virgil-sdk)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)
[![Documentation YARD](https://img.shields.io/badge/docs-yard-blue.svg)](https://virgilsecurity.github.io/virgil-sdk-ruby)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [JWT Generation](#jwt-generation) | [Ruby SDK V4](#ruby-sdk-v4) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communication, securely store data, provide passwordless login, and ensure data integrity.

The Virgil SDK allows developers to get up and running with Virgil API quickly and add full end-to-end security to their existing digital solutions to become HIPAA and GDPR compliant and more.

## SDK Features
- Communicate with Virgil Cards Service
- Manage users' public keys
- Encrypt, sign, decrypt and verify data
- Store private keys in secure local storage
- Use Virgil Crypto Library

## JWT Generation
To make calls to Virgil Services (for example, to register user's card on Virgil Cloud), you have to generate a JSON Web Token ("JWT") that contains the user's `identity`, which is a string that uniquely identifies each user in your application.

To start generating a JWT, switch to [JWT-V5 branch](https://github.com/VirgilSecurity/virgil-sdk-ruby/tree/jwt-v5) and follow the README instructions.

## Ruby SDK V4
Switch to [V4 branch](https://github.com/VirgilSecurity/virgil-sdk-ruby/tree/v4) to find out more information on how to start working with Virgil Ruby SDK V4.

## Docs

Virgil Security has a powerful set of APIs, and the [Developer Documentation](https://developer.virgilsecurity.com/) can get you started today.

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support

Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).


[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-crypto

