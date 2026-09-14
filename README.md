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

## Authorizations

This package stores tokens as "authorizations" in a dedicated database
table.

For example, the authorization code flow ends with a token, which is
stored in the authorizations table. While the flow is in progress, this
package keeps track of its "state" in the cache
"Flownative_OAuth2_Client_State", in order to make sense of the incoming
"finish authorization" request. Another example is the client
credentials flow, where an access token is stored in the authorizations
table which is needed for executing authorized requests to the
respective service.

### Token lifetime

An authorization expires together with its token. Expired
authorizations are removed by the garbage collection.

Tokens from the authorization code flow which don't specify an
expiration time get a default lifetime of 600 seconds (10 minutes). An
authorization code flow which has not finished expires after one hour.
Tokens from the client credentials flow without an expiration time
don't expire. They are replaced when a new token is requested.

The default token lifetime and the frequency of the garbage collection
can be configured:

```yaml
Flownative:
  OAuth2:
    Client:
      garbageCollection:
        # The probability in percent that a request which used an OAuth client
        # removes expired authorizations and states when it ends.
        #
        # Examples:
        #    1     (a 1 % chance to clean up)
        #   20     (a 20 % chance to clean up)
        #    0.001 (a 0.001 % chance to clean up)
        probability: 1
      token:
        # Lifetime in seconds of tokens from the authorization code flow which
        # do not specify an expiration time
        defaultLifetime: 600
```

Note: By setting the `defaultLifetime` to `null`, tokens without an
expiration time won't expire.

Instead of relying on chance, you can remove expired authorizations on
a fixed schedule, for example with a cron job. Set the `probability` to
`0` and run the following command regularly:

```bash
$ ./flow oauth:collectgarbage
```

### Authorization metadata

Authorizations also may contain developer-provided metadata. For
example, you may attach an account identifier to an authorization when
an authorization process starts and use that information when
authorization finishes to make sure that the authorization is only used
for a specific account (or customer number, or participant id).

To set metadata, you need to know the authorization id when starting the
authorization code flow. This code could be used in an overloaded
`startAuthorizationAction()`:

```php
$authorizationId = $oAuthClient->generateAuthorizationIdForAuthorizationCodeGrant($this->appId);
$loginUri = $oAuthClient->startAuthorizationWithId(
    $authorizationId,
    $this->appId,
    $this->appSecret,
    $returnToUri,
    $scope
);
$oAuthClient->setAuthorizationMetadata($authorizationId, json_encode($metadata));
```

And later, when the authorization is finished, you may retrieve the
metadata as follows:

```php
$authorization = $oAuthClient->getAuthorization($authorizationId);
$metadata = json_decode($authorization->getMetadata());
```

## Encryption

By default, access tokens are serialized and stored unencrypted in the
"authorizations" database table. You can improve the security of your
application by enabling the encrypted-at-rest feature of this package.
When active, it encrypts tokens before storing them in the database and
decrypts them automatically when they are retrieved. The secret key
which is needed for encryption and decryption is not stored in the
database.

This package uses the "ChaCha20-Poly1305-IETF" construction for
authenticated encryption / decryption of serialized tokens, provided by
the ["sodium" PHP extension](https://www.php.net/sodium).

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
this one:

```
ChaCha20-Poly1305-IETF$Mjdj4s9IFrPp6HFK$k9v3x…KQ==
```

There are three parts in this string, separated by two dollar signs:

1. the construction used for encryption ("ChaCha20-Poly1305-IETF")
2. the nonce used for this particular entry ("Mjdj4s9IFrPp6HFK")
3. the encrypted data ("k9v3x…KQ==")
