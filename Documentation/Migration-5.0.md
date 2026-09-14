# Migrating from 4.x to 5.0

Version 5.0 modernizes the package and changes how authorizations are
stored, expire and are requested. Most applications only need to check
the requirements and the scopes of their client credentials requests.
Applications which extend `OAuthClient` or call its methods directly
should read the whole guide.

- [Requirements](#requirements)
- [Encryption Key](#encryption-key)
- [Client Credentials](#client-credentials)
- [Authorization Code Flow](#authorization-code-flow)
- [Expiration and Garbage Collection](#expiration-and-garbage-collection)
- [Changes for Code Which Extends or Calls the Client](#changes-for-code-which-extends-or-calls-the-client)

## Requirements

- PHP 8.3, 8.4 or 8.5, with the "sodium" extension
- Flow 8.3 (8.3.13 or later), Flow 8.4, or Flow 9.0 or later
- league/oauth2-client 2.9 and Guzzle 7.9

The pure PHP polyfill paragonie/sodium_compat is no longer installed.
The "sodium" extension ships with all common PHP distributions.

## Encryption Key

If you configured `Flownative.OAuth2.Client.encryption.base64EncodedKey`,
the key must now decode to exactly 32 bytes. Otherwise, the encryption
service throws an exception when it is initialized. Before, a key of the
wrong length only failed when a token was encrypted or decrypted.

Generate a suitable key with:

```bash
./flow oauth:generateencryptionkey
```

## Client Credentials

### The Scope Is Sent to the Authorization Server

`requestAccessToken()` now sends the given scope to the token endpoint,
unless the scope is empty.

Version 4 never sent the scope. The authorization server therefore
issued a token with its default scope, while the stored authorization
claimed the requested scope. Sending the scope lets the server restrict
the token to the rights which the application asked for, as recommended
by the [OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700#section-2.3).

This can break existing applications:

- If the client is not allowed to request a scope, the server now
  rejects the request, usually with the error `invalid_scope`. Before,
  the value was silently ignored.
- The token only contains the requested rights. If your application
  relied on the default scope of the server, pass an empty scope.
- Some servers expect a specific format. Microsoft Entra ID, for
  example, only accepts `{resource}/.default`.

Check the scopes of all client credentials requests before you upgrade.
Version 6.0 of flownative/openidconnect-client no longer adds `openid`
to the scope of client credentials requests.

### Tokens Are Requested Again Once

`Authorization::generateAuthorizationIdForClientCredentialsGrant()` no
longer takes the client secret, and the id is calculated differently.
After the upgrade, every application requests its client credentials
tokens once more.

Authorizations stored by version 4 are not used anymore. If they have
an expiration time, the garbage collection removes them. Otherwise,
find them with `./flow oauth:listauthorizations` and remove them with
`./flow oauth:removeauthorizations --id <authorization id>`.

### Other Changes

- An existing token is replaced only after the new token was issued.
  If the request fails, the previous token stays available.
- The additional parameters must not contain `grant_type`, `client_id`,
  `client_secret`, `redirect_uri`, `scope`, `code`, `code_verifier` or
  `refresh_token`. The client sets them itself and throws an
  `InvalidArgumentException` otherwise.
- The client credentials request no longer sends a redirect URI.
- If the token response contains a scope, the authorization stores it
  instead of the requested scope.

## Authorization Code Flow

### Authorizations Are Stored When the Flow Finishes

Starting a flow no longer writes to the database. The data of a flow in
progress is kept in the state cache, and the authorization is stored
when the flow finishes.

Metadata therefore can no longer be attached with
`setAuthorizationMetadata()` while the flow is in progress. Pass it to
`startAuthorization()` or `startAuthorizationWithId()` instead:

```php
$authorizationUri = $oAuthClient->startAuthorization($clientId, $clientSecret, $returnToUri, $scope, [], json_encode($metadata));
```

`setAuthorizationMetadata()` still changes the metadata of a finished
authorization.

### Refused Authorizations

If the authorization server refuses an authorization, for example
because the user denied access, the browser now returns to the return
URI. The error code is in the query parameter which
`OAuthClient::generateAuthorizationErrorQueryParameterName()` returns.
Codes which RFC 6749 and OpenID Connect don't define arrive as
`server_error`. Version 4 answered such a return with a server error.

### Unknown States

A malformed, unknown, expired or already used state now results in
status 400 instead of 500. This happens, for example, when a user
reloads the page of a finished login.

### Redirect URI

The redirect URI is rendered once when the flow starts and stored with
the state. Outside of a web request, for example in a command or a job,
rendering it requires the setting `Neos.Flow.http.baseUri`. Without it,
an `OAuthClientException` explains the problem.

### Scope

The scope of a finished authorization comes from the token response, or
from the scope requested at the start. The `scope` parameter of the
callback URL is ignored, and `finishAuthorization()` no longer takes a
scope argument.

## Expiration and Garbage Collection

- Expiration times are stored in UTC. Before, they depended on the
  default time zone of PHP, so authorizations were removed too early
  east of UTC and too late west of it.
- The garbage collection deletes expired authorizations with one query
  and runs at most once per request. The probability is now calculated
  correctly for all values, so a probability like `0.005` works.
- To clean up on a fixed schedule, set
  `Flownative.OAuth2.Client.garbageCollection.probability` to `0` and
  run `./flow oauth:collectgarbage` regularly, for example as a cron
  job.
- `Flownative.OAuth2.Client.token.defaultLifetime` now applies to all
  tokens without an expiration time, including client credentials
  tokens. It is counted from the moment the token is issued.

## Changes for Code Which Extends or Calls the Client

- Constants and most injected properties of `OAuthClient` and
  `Authorization` have native types. Subclasses which redeclare such a
  property must declare the same type.
- `OAuthClient::removeExpiredAuthorizations()` and the property
  `garbageCollectionProbability` were removed. The new
  `GarbageCollector` replaces them.
- `finishAuthorization(string $stateIdentifier, string $code)` lost its
  scope argument. `finishAuthorizationWithError()` handles refused
  authorizations. Both throw an `UnknownStateException` for unknown
  states.
- `createOAuthProvider()` has an additional optional argument for the
  redirect URI.
- `renderFinishAuthorizationUri()` may throw an `OAuthClientException`.
- `startAuthorization()` and `startAuthorizationWithId()` have an
  additional optional argument for metadata.
- `Authorization::generateAuthorizationIdForClientCredentialsGrant()` no
  longer takes the client secret.
