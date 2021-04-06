[![MIT license](http://img.shields.io/badge/license-MIT-brightgreen.svg)](http://opensource.org/licenses/MIT)
[![Packagist](https://img.shields.io/packagist/v/flownative/oauth2-client.svg)](https://packagist.org/packages/flownative/oauth2-client)
[![Maintenance level: Love](https://img.shields.io/badge/maintenance-%E2%99%A1%E2%99%A1%E2%99%A1-ff69b4.svg)](https://www.flownative.com/en/products/open-source.html)

# OAuth 2.0 Client for Flow Framework

This [Flow](https://flow.neos.io) package provides an OAuth 2.0 client
SDK. Even though it can be used as a generic OAuth2 client, it was
developed as a backing library for the
[OpenID Connect package](https://github.com/flownative/flow-openidconnect-client).
That's why documentation for this package is a bit sparse at the moment
and examples for generic use are missing.

At the time of writing (November 2020), this package is actively
maintained and there are plans for improving functionality, test
coverage and documentation.

## Authorizations

This package stores states and tokens as "authorizations" in a dedicated
database table.  

For example, during the authorization code flow, this package needs to
keep track of a "state" in order to make sense of an incoming "finish
authorization" request. Another example is the client credentials flow,
where an access token is stored in the authorizations table which is
needed for executing authorized requests to the respective service.

### Token lifetime

New Authorization tokens are created with a lifetime of 600 seconds
(10 minutes) by default.
The expiration date is updated during authentication if a different
`expires` parameter is specified in the OAuth2 access token.

The default token lifetime and frequency of expired tokens to be removed
automatically can be configured:

```yaml
Flownative:
  OAuth2:
    Client:
      garbageCollection:
        # The probability in percent of a client shutdown triggering a garbage
        # collection which removes expired tokens.
        #
        # Examples:
        #    1    (would be a 1% chance to clean up)
        #   20    (would be a 20% chance to clean up)
        #    0.42 (would be a 0.42 % chance to clean up)
        probability: 1
    token:
      # default lifetime of new tokens in seconds
      defaultLifetime: 600
```

Note: By setting the `defaultLifetime` to `null`, new tokens won't expire
by default.

## Encryption

By default, access tokens are serialized and stored unencrypted in the
"authorizations" database table. You can improve the security of your
application by enabling the encrypted-at-rest feature of this package.
when active, it will encrypt tokens before storing them in the database
and decrypt them automatically when they are retrieved. The secret key
which is needed for encryption and decryption is not stored in the
database.

This package uses the "ChaCha20-Poly1305-IETF" construction for
authenticated encryption / decryption of serialized tokens. It uses the
["sodium" PHP extension](https://www.php.net/sodium) if installed, or
[a polyfill implementation](https://packagist.org/packages/paragonie/sodium_compat)
in pure PHP.

### Generating a Secret Key

The OAuth2 Flow package provides a CLI command for generating encryption
keys suitable for the currently supported encryption method:

```bash
$ ./flow oauth:generateencryptionkey
qpBzrH7icQqBKenvk8wTKROv4qcJNxslzdGo3IKXmws=
```

The key is base64-encoded in order to simplify handling and being able
to pass the key via Flow settings.

### Enabling Encryption

Set the encryption key via Flow settings (for example in your global
"Configuration/Settings.yaml"). Make sure to deploy this setting
securely, for example by creating the Settings file during deployment or
by using environment variables.

```yaml
Flownative:
  OAuth2:
    Client:
      encryption:
        base64EncodedKey: 'qpBzrH7icQqBKenvk8wTKROv4qcJNxslzdGo3IKXmws='
```

### Verifying Encryption Configuration

When you have set the encryption key, test that everything is working as
expected. Run your application so that a new authorization is created.
Check the database table `flownative_oauth2_client_authorization`: the
column `serializedaccesstoken` should be empty and the column
`encryptedserializedaccesstoken` should contain a long string similar to
his one:

```
ChaCha20-Poly1305-IETF$Mjdj4s9IFrPp6HFK$k9v3x…KQ==
```

There are three parts in this string, separated by two dollar signs:

1. the construction used for encryption ("ChaCha20-Poly1305-IETF")
2. the nonce used for this particular entry ("Mjdj4s9IFrPp6HFK")
3. the encrypted data ("k9v3x…KQ==")
