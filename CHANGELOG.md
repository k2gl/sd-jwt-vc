# Changelog

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
