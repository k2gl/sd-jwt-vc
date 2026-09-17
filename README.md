# k2gl/sd-jwt-vc

[![CI](https://img.shields.io/github/actions/workflow/status/k2gl/sd-jwt-vc/ci.yml?branch=main&label=CI&logo=github)](https://github.com/k2gl/sd-jwt-vc/actions)
[![Latest Stable Version](https://img.shields.io/packagist/v/k2gl/sd-jwt-vc)](https://packagist.org/packages/k2gl/sd-jwt-vc)
[![Total Downloads](https://img.shields.io/packagist/dt/k2gl/sd-jwt-vc)](https://packagist.org/packages/k2gl/sd-jwt-vc)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%209-2a5ea7)](https://phpstan.org/)
[![License](https://img.shields.io/packagist/l/k2gl/sd-jwt-vc)](https://packagist.org/packages/k2gl/sd-jwt-vc)

SD-JWT-based Verifiable Credentials
([draft-ietf-oauth-sd-jwt-vc](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/))
in pure PHP: issue and verify `dc+sd-jwt` credentials — the format HAIP and the EU Digital
Identity Wallet build on. RFC 9901 processing is provided by
[k2gl/sd-jwt](https://github.com/k2gl/sd-jwt); this package adds the credential layer:
the `typ`/`vct` rules, the protected-claims rules, and Issuer key discovery.

Tracks **draft -19** (in IETF Last Call). The test suite verifies the draft's own worked
examples byte for byte. The `typ` is `dc+sd-jwt`; the pre-2024 `vc+sd-jwt` is refused unless
you opt in (`acceptLegacyType: true`) — draft -19 ended the transition period.

## Install

```bash
composer require k2gl/sd-jwt-vc
```

Requires PHP 8.1+. The JWT VC Issuer Metadata resolver speaks PSR-18/PSR-17, so bring any
HTTP client (or none, if you pin keys or use x5c).

## Usage

### Verify a presentation (Verifier / relying party)

```php
use K2gl\SdJwt\KeyBinding;
use K2gl\SdJwtVc\JwtVcIssuerMetadata;
use K2gl\SdJwtVc\SdJwtVcVerifier;

$verifier = new SdJwtVcVerifier;

$credential = $verifier->verifyPresentation(
    $compact,
    new JwtVcIssuerMetadata($psr18Client, $psr17RequestFactory), // resolves /.well-known/jwt-vc-issuer
    KeyBinding::required(audience: 'https://verifier.example.org', nonce: $nonce),
);

$credential->vct();      // "https://credentials.example.com/identity_credential"
$credential->claims();   // the Processed SD-JWT Payload
$credential->status();   // the status claim, if any (e.g. Token Status List reference)
```

Key discovery mechanisms (Section 2.5), all pluggable via `IssuerKeyResolver`:

- `JwtVcIssuerMetadata` — web-based resolution from `/.well-known/jwt-vc-issuer`, `jwks`
  or `jwks_uri`, kid-aware, `issuer`⇔`iss` identity enforced.
- `X5cIssuerKeys` — the `x5c` header chain, validated against your trust anchors
  (signatures, validity windows, anchor membership; revocation is out of scope).
- `StaticIssuerKeys` — keys pinned in configuration.
- Any k2gl/dsse `Verifier` directly, when there is exactly one trusted key.

### Issue a credential

```php
use K2gl\SdJwt\Jws\JwsSigner;
use K2gl\SdJwt\Sd;
use K2gl\SdJwtVc\SdJwtVcIssuer;

$issuer = new SdJwtVcIssuer(JwsSigner::es256FromPem($pem));

$credential = $issuer->issue([
    'vct' => 'https://credentials.example.com/identity_credential',
    'iss' => 'https://issuer.example.com',
    'iat' => time(),
    'cnf' => ['jwk' => $holderJwk],
    'given_name' => Sd::hide('John'),
    'birthdate' => Sd::hide('1983-07-29'),
]);

$compact = $credential->toCompact();
```

The `typ` header is always `dc+sd-jwt`; `vct` is required; the claims that the draft
forbids disclosing selectively (`iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`,
`aka_vcts`, `status`) are rejected if wrapped in `Sd::hide()`, sub-claims included — and
rejected again at verification time if a foreign issuer tried it. `aka_vcts`, the additional
types a credential is also known as, is validated on both sides and read back with
`$credential->alsoKnownAsTypes()`.

Presentation building (selecting disclosures, Key Binding) is the Holder side and lives in
k2gl/sd-jwt's `Presentation`.

### Fetching metadata safely

`JwtVcIssuerMetadata` dereferences URLs derived from the credential's `iss` claim, so it
follows the draft's Section 3 retrieval rules rather than trusting the network: a document
counts only when the response is 2xx *and* `application/json`; redirects are followed by
hand (three at most) so that every hop, like the original URL, passes the `UrlPolicy` —
HTTPS only, no loopback, link-local or private address, and DNS names resolved and checked
the same way; the body is read up to a size limit (1 MiB by default). Time limits are the
PSR-18 client's job — configure its timeout. Tune the policy per deployment:

```php
new JwtVcIssuerMetadata(
    $psr18Client,
    $psr17RequestFactory,
    urlPolicy: new UrlPolicy(resolveHosts: false), // e.g. behind an egress proxy that enforces this itself
    maxRedirects: 1,
    maxBytes: 256 * 1024,
);
```

### Type Metadata

A credential type can publish Type Metadata (Section 5): a human-readable name, display
and rendering hints for wallets, and per-claim rules — which claims must or must not be
selectively disclosable (`sd`), which are mandatory. Give the verifier a
`TypeMetadataResolver` and it processes the metadata for every credential: the `extends`
chain is resolved (extended types first, circular chains refused), `vct#integrity` and
`extends#integrity` are checked as W3C SRI digests, and the presentation is validated
against the effective claim metadata. A credential whose metadata cannot be obtained is
rejected, as Section 5.7 requires once metadata is part of the policy.

```php
use K2gl\SdJwtVc\HttpTypeMetadata;
use K2gl\SdJwtVc\StaticTypeMetadata;

// from the vct URL itself, under the same Section 3 retrieval rules and UrlPolicy
$verifier = new SdJwtVcVerifier(typeMetadata: new HttpTypeMetadata($psr18Client, $psr17RequestFactory));

// or from documents you hold — a registry, a cache filled ahead of time, non-URL types
$verifier = new SdJwtVcVerifier(typeMetadata: (new StaticTypeMetadata)->add($vct, $typeMetadataJson));

$credential = $verifier->verifyPresentation($compact, $issuerKeys, $keyBinding);

$metadata = $credential->typeMetadata();   // ResolvedTypeMetadata
$metadata->claims();                       // ClaimMetadata after extension: path, sd(), mandatory(), display, svgId
$metadata->display();                      // the display entries of the nearest type that defines any
$metadata->chain();                        // the documents, the type itself first
```

What is validated: every claim path must evaluate against the credential (a string
component on a non-object, or an index on a non-array, is an error), and every claim a
path selects must be selectively disclosable exactly as its `sd` says — "disclosable"
meaning directly represented as a Disclosure, not merely inside one; array positions
count the elements as issued, so a withheld element still satisfies `"sd": "always"`.
`mandatory` is not checked by a Verifier: the draft forbids reading the absence of a
selectively disclosable claim from a presentation as the Issuer having left it out.
Display and rendering metadata are handed out as data; rendering is the wallet's job.
The draft's own example type (Appendix A.2) is a fixture of the test suite.

### Check revocation

A verified credential can still have been revoked. The draft's status mechanism is the
Token Status List, and it requires the Status List Token to be a JWT — which is what
[k2gl/token-status-list](https://github.com/k2gl/token-status-list) implements:

```php
use K2gl\TokenStatusList\StatusListResolver;
use K2gl\TokenStatusList\StatusReference;

$status = $credential->status();

if ($status !== null) {
    $resolver = new StatusListResolver($psr18Client, $psr17RequestFactory, $statusIssuerKey, cache: $psr16Cache);

    if (! $resolver->check(StatusReference::fromClaim($status))->isValid()) {
        // revoked or suspended
    }
}
```

## Scope

- `dc+sd-jwt` issuance and verification per draft -19, compact and JWS JSON serialization
  (via k2gl/sd-jwt 1.1).
- Key discovery: JWT VC Issuer Metadata (PSR-18, Section 3 retrieval rules), x5c chains,
  pinned keys.
- `status` claim surfaced for the check; the Token Status List itself is
  k2gl/token-status-list.
- Type Metadata (Section 5): retrieval from the `vct` URL or a local registry, integrity
  metadata, `extends` chains, claim metadata validation (`sd`); display and rendering
  metadata as data. Not covered: `mandatory` (a Verifier cannot check it) and rendering.

## License

MIT © [Nick Harin](https://github.com/k2gl)
