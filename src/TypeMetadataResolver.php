<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

/**
 * A way to obtain the Type Metadata document for a credential type
 * (draft-ietf-oauth-sd-jwt-vc Section 5.3): from the `vct` URL itself
 * ({@see HttpTypeMetadata}), from a registry or cache ({@see StaticTypeMetadata}),
 * or however an ecosystem defines it. Whatever the source, the document's
 * `vct` must be the type asked for, and when integrity metadata is given
 * (`vct#integrity`, `extends#integrity`) the octets must match it.
 */
interface TypeMetadataResolver
{
    /**
     * @throws Exception\TypeMetadataException when the document cannot be obtained or is unusable
     */
    public function resolve(string $vct, ?string $integrity): TypeMetadata;
}
