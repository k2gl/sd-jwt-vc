# Changelog

## 2.1.0

- **Type Metadata** (draft -19 Section 5). `SdJwtVcVerifier` takes a `TypeMetadataResolver`
  and then processes the metadata of every credential it verifies: `HttpTypeMetadata`
  fetches it from the `vct` URL under the Section 3 retrieval rules (same `UrlPolicy`,
  redirect and size limits as key discovery), `StaticTypeMetadata` serves documents held
  locally; `vct#integrity` and `extends#integrity` are checked as W3C SRI digests
  (Section 6); the `extends` chain is resolved extended-type-first with circular chains
  refused (Section 7.4); claim metadata is merged per Section 5.6.5, with `sd` fixed to
  always/never and `mandatory: true` not loosenable by an extension.
- The presentation is validated against the effective claim metadata: paths are evaluated
  per Section 5.6.1.2 against the arrays as issued (k2gl/sd-jwt 1.2), and a claim that is
  not selectively disclosable as its `sd` requires rejects the credential. `mandatory` is
  left to Holders, as the draft asks of Verifiers.
- `VerifiedSdJwtVc::typeMetadata()` returns the `ResolvedTypeMetadata` — chain, effective
  claims, display; `disclosedPaths()` / `undisclosedPaths()` are exposed too.
- The Section 3 HTTP retrieval moved into a shared internal fetcher; `JwtVcIssuerMetadata`
  behaves as before.
- Requires k2gl/sd-jwt ^1.2.

## 2.0.0

Catches up with draft-ietf-oauth-sd-jwt-vc-19.

- **Breaking:** the verifier no longer accepts the pre-2024 `vc+sd-jwt` typ by default —
  draft -19 removed the transition period. Pass `acceptLegacyType: true` to keep accepting it.
- **Breaking:** `JwtVcIssuerMetadata` applies the Section 3 retrieval rules: a document must
  come back 2xx with `application/json`, redirects are followed at most three times and only
  to HTTPS URLs, every URL (redirect targets included) is checked by the new `UrlPolicy`
  against loopback, link-local and private addresses (DNS names are resolved), and the body
  is read up to 1 MiB. All of it is configurable through the constructor.
- The `aka_vcts` claim: validated on issuance and verification, protected from selective
  disclosure, exposed as `VerifiedSdJwtVc::alsoKnownAsTypes()`.
- Protected claims are protected together with their sub-claims, on both sides (needs
  k2gl/sd-jwt 1.1 for `disclosedPaths()`).
- The JWS JSON serialization is accepted wherever a compact string is, via k2gl/sd-jwt 1.1.
- `composer suggest`s k2gl/token-status-list; the README shows the status check.

## 1.0.0

- Initial release: SD-JWT-based Verifiable Credentials per draft-ietf-oauth-sd-jwt-vc-17.
- `SdJwtVcIssuer` — `dc+sd-jwt` credentials over k2gl/sd-jwt, with the `vct` requirement
  and non-disclosable protected claims enforced at issuance.
- `SdJwtVcVerifier` — RFC 9901 verification plus the VC rules (`typ`, `vct`, protected
  claims), accepting the legacy `vc+sd-jwt` typ by default for the transition period.
- Issuer key discovery per Section 2.5: `JwtVcIssuerMetadata`
  (`/.well-known/jwt-vc-issuer` over PSR-18, `jwks`/`jwks_uri`, kid-aware),
  `X5cIssuerKeys` (chain validation against configured trust anchors), and
  `StaticIssuerKeys`.
- Test vectors: the draft's Section 2.3 worked examples (issuance and presentation with
  Key Binding).
