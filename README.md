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

When upgrading from version 4, read the
[migration guide](Documentation/Migration-5.0.md).

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

Tokens which don't specify an expiration time get a default lifetime of
600 seconds (10 minutes). A token of the client credentials flow is
replaced only when the new token was issued. An authorization code flow
is stored as an authorization only when it finishes. Until then, it is
kept in the state cache, where it expires after one hour.

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
        # Lifetime in seconds of tokens which do not specify an expiration time
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

Pass the metadata when you start the authorization code flow. It is
stored together with the authorization when the flow finishes. The
browser binding ties the authorization to the browser which starts it,
so the response which redirects the browser must set its cookie. The
client class provides the client secret in `getClientSecret()`.

```php
$browserBinding = BrowserBinding::generate();
$loginUri = $oAuthClient->startAuthorization(
    $this->appId,
    $returnToUri,
    $scope,
    $browserBinding,
    [],
    json_encode($metadata)
);
$this->response->setCookie($browserBinding->createCookie());
$this->redirectToUri($loginUri);
```

When the authorization is finished, the return URI contains a handle of
the authorization. The handle can only be used once, within a minute
and by the same browser. You may retrieve the metadata as follows:

```php
$authorizationHandle = $request->getQueryParams()[OAuthClient::generateAuthorizationIdQueryParameterName($serviceType)];
$authorization = $oAuthClient->claimAuthorization($authorizationHandle, $request->getCookieParams());
$metadata = json_decode($authorization->getMetadata());
```

To change the metadata of a finished authorization, use
`setAuthorizationMetadata()`.

### Refused authorizations

If the OAuth server refuses an authorization, for example because the
user denied access, the browser still returns to the return URI. Instead
of the authorization id, the URI then contains the error code:

```php
$errorParameterName = OAuthClient::generateAuthorizationErrorQueryParameterName($serviceType);
$error = $request->getQueryParams()[$errorParameterName] ?? null;
```

The error codes are the ones defined by
[RFC 6749](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1) and
[OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html#AuthError),
for example `access_denied`. Any other code arrives as `server_error`.

## Returns through a relay

Some OAuth servers accept only redirect URIs which are registered
exactly. An application which serves many host names, for example one
per customer, can then let all returns arrive at a single relay host.
The relay forwards each return, with its `code` and `state`, to the
host which started the authorization. That host finishes the
authorization as usual: it checks the cookie of the browser binding,
sends the PKCE verifier and repeats the redirect URI of the relay in
the token request.

Both options are off by default. A client enables them by overriding
two methods:

```php
protected function getRedirectUri(): ?string
{
    return 'https://login.example.com/oauth2/oidc/my-service/finishauthorization';
}

protected function getStateSigner(): ?StateSigner
{
    return StateSigner::fromBase64EncodedSecretKey('cell-1', $this->base64EncodedStateSigningKey, ['*.cell-1.example.com']);
}
```

`getRedirectUri()` replaces the URI of the finish authorization action
in the authorization request and in the token request. With
`getStateSigner()`, the state names the host of the current request,
signed with Ed25519, so that the relay knows where to forward the
return. The state is then up to 1,024 characters long, instead of 32.
The signature covers the state behind the prefix
`flownative-oauth2-state.`, so that it is never valid for another
protocol. A client whose redirect URI points to another host, but which
has no state signer, logs a warning when it starts an authorization:
the relay can't forward such a return and answers with an error.

Both are new protected methods of `OAuthClient`. A subclass which
already has a method of the same name, with another signature or
visibility, must rename or adapt it.

Without a configured `Neos.Flow.http.baseUri`, the host of the current
request comes from the `Host` or `X-Forwarded-Host` header, which the
browser chooses. The signer therefore takes the host patterns of the
tenants your installation knows, and refuses to sign any other host:
the authorization then fails with an `OAuthClientException`, and no
state is issued. List only hosts which you have resolved to a known
tenant, never a pattern which also matches hosts you don't serve.

If your patterns contain a wildcard, pass a check as the fourth
argument, which tells whether a host belongs to a known tenant. The
signer asks it for every host which matches the patterns, in lower
case and with the port if it is not the default one (such as
`acme.cell-1.example.com:8443`), and refuses the host if the check
returns `false` or throws an exception:

```php
StateSigner::fromBase64EncodedSecretKey('cell-1', $this->base64EncodedStateSigningKey, ['*.cell-1.example.com'], $this->tenantRepository->hasHostName(...));
```

Generate a key pair for each installation which sends returns through
the relay, and give the secret key only to that installation. Pipe the
output straight into your secret store, and never run the command in a
CI job whose log keeps it:

```bash
$ ./flow oauth:generatestatesigningkey | your-secret-store-import
```

The relay knows only the public keys. It verifies the state, needs no
database and no cache, and restricts each key to the host names of its
installation. A host pattern `*.example.com` matches exactly one
further label, and the domain of a wildcard needs at least two labels,
so `*.com` is refused. Wildcards over public suffixes of two labels,
such as `*.co.uk` or `*.github.io`, are not detected, so don't
configure them. An IP address is only accepted if a pattern
names it exactly. This also holds for the notations which browsers
resolve to an IP address, such as `2130706433`, `0x7f000001` or
`127.1`:

```php
$verifier = new StateVerifier([
    StateVerificationKey::fromBase64EncodedPublicKey('cell-1', $base64EncodedPublicKey, ['*.cell-1.example.com', 'customer.example.org']),
]);
try {
    $targetHost = $verifier->verify($state)->targetHost;
} catch (InvalidSignedStateException) {
    // answer with an error page, never forward the browser
}
```

A pattern which names a single host of a customer's own domain, such
as `customer.example.org`, must be removed as soon as the customer
leaves or points the domain elsewhere. Otherwise a valid signature
sends the code to a server which no longer belongs to the customer.
An empty list of patterns is refused.

A wildcard pattern needs the same care for its whole domain. If your
ingress routes every subdomain to the application, a signer with
`*.cell-1.example.com` signs any host which a request names in its
`Host` header. Should a subdomain then point elsewhere in DNS, for
example through a dangling CNAME or an expired record of a customer,
a valid signature sends the code of a victim to whoever controls that
target. Keep the wildcard domain clean, remove every record as soon as
its tenant is gone, and give the signer a check for known tenants.

`StateVerificationKey::allowingAnyHost()` trusts a key with any host
name; use it only if the key's installation is the only one which may
send returns through the relay. The verifier also refuses a state which
is older than one hour, the lifetime of the state cache, with a clock
skew of one minute. Pass `maximumAge` to the verifier if you changed
that lifetime, the `defaultLifetime` of the cache
`Flownative_OAuth2_Client_State` in `Caches.yaml`.

The relay forwards to `https://` followed by the verified target host
and the path of the finish authorization action, which it knows from
its configuration. From the query of the return it copies only `code`,
`state` and `error`, and drops everything else.
The relay builds this URI itself and never takes the scheme, the host
or the path from the request, or else anybody with a valid state could
use it to redirect browsers to any path of a target host. Without a
valid signature, the relay must not forward at all.
Otherwise an attacker could start an authorization with your client id
and the redirect URI of the relay, and let the code of a victim land on
their own server.

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
