<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Tests;

use K2gl\SdJwt\KeyBinding;
use K2gl\SdJwtVc\Exception\IssuerKeyResolutionFailed;
use K2gl\SdJwtVc\JwtVcIssuerMetadata;
use K2gl\SdJwtVc\SdJwtVcVerifier;
use K2gl\SdJwtVc\Tests\Support\SdJwtVcTestCase;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(JwtVcIssuerMetadata::class)]
final class JwtVcIssuerMetadataTest extends SdJwtVcTestCase
{
    #[DataProvider('wellKnownUrls')]
    public function testBuildsTheWellKnownUrl(string $issuer, string $expected): void
    {
        // act + assert
        fact(JwtVcIssuerMetadata::wellKnownUrl($issuer))->is($expected);
    }

    public function testResolvesTheDraftExampleViaInlineJwks(): void
    {
        // arrange
        $metadata = [
            'issuer' => self::DRAFT_ISSUER,
            'jwks' => ['keys' => [self::draftIssuerJwk() + ['kid' => 'doc-signer-05-25-2022']]],
        ];

        // assert: stub serves the metadata document inline
        $resolver = new JwtVcIssuerMetadata(
            $this->httpClient([
                'https://example.com/.well-known/jwt-vc-issuer/issuer' => $metadata,
            ]),
            new Psr17Factory,
        );

        // act
        $verifier = new SdJwtVcVerifier(clock: self::DRAFT_CLOCK);
        $credential = $verifier->verifyPresentation(
            self::fixture('draft17/presentation-sd-jwt-vc-kb.txt'),
            $resolver,
            KeyBinding::required(audience: 'https://example.com/verifier', nonce: '1234567890'),
        );

        // assert: disclosed claim survives
        fact($credential->claims()['is_over_65'])->true();
    }

    public function testResolvesViaJwksUri(): void
    {
        // assert: stub serves metadata plus the referenced key set
        $resolver = new JwtVcIssuerMetadata(
            $this->httpClient([
                'https://example.com/.well-known/jwt-vc-issuer/issuer' => [
                    'issuer' => self::DRAFT_ISSUER,
                    'jwks_uri' => 'https://keys.example.com/set.jwks',
                ],
                'https://keys.example.com/set.jwks' => ['keys' => [self::draftIssuerJwk()]],
            ]),
            new Psr17Factory,
        );

        // act
        $credential = (new SdJwtVcVerifier(clock: self::DRAFT_CLOCK))->verify(
            self::fixture('draft17/issuance-sd-jwt-vc.txt'),
            $resolver,
        );

        // assert: issuer resolved through the redirect
        fact($credential->issuer())->is(self::DRAFT_ISSUER);
    }

    #[DataProvider('invalidIssuers')]
    public function testRejectsNonHttpsOrQueryIssuers(string $issuer): void
    {
        // act + assert
        fact(static fn () => JwtVcIssuerMetadata::wellKnownUrl($issuer))->throws(IssuerKeyResolutionFailed::class);
    }

    public function testIssuerMismatchIsRejected(): void
    {
        // assert: stub reports a foreign "issuer"
        $resolver = new JwtVcIssuerMetadata(
            $this->httpClient([
                'https://example.com/.well-known/jwt-vc-issuer/issuer' => [
                    'issuer' => 'https://evil.example.com',
                    'jwks' => ['keys' => [self::draftIssuerJwk()]],
                ],
            ]),
            new Psr17Factory,
        );

        // act + assert
        fact(static fn () => (new SdJwtVcVerifier(clock: self::DRAFT_CLOCK))->verify(
            self::fixture('draft17/issuance-sd-jwt-vc.txt'),
            $resolver,
        ))->throws(IssuerKeyResolutionFailed::class, 'identical');
    }

    public function testBothJwksAndJwksUriAreRejected(): void
    {
        // assert: stub reports both "jwks" and "jwks_uri"
        $resolver = new JwtVcIssuerMetadata(
            $this->httpClient([
                'https://example.com/.well-known/jwt-vc-issuer/issuer' => [
                    'issuer' => self::DRAFT_ISSUER,
                    'jwks' => ['keys' => [self::draftIssuerJwk()]],
                    'jwks_uri' => 'https://keys.example.com/set.jwks',
                ],
            ]),
            new Psr17Factory,
        );

        // act + assert
        fact(static fn () => $resolver->resolve(self::DRAFT_ISSUER, (object) []))
            ->throws(IssuerKeyResolutionFailed::class);
    }

    public function testHttpErrorIsRejected(): void
    {
        // assert: stub 404s every URL
        $resolver = new JwtVcIssuerMetadata($this->httpClient([]), new Psr17Factory);

        // act + assert
        fact(static fn () => $resolver->resolve(self::DRAFT_ISSUER, (object) []))
            ->throws(IssuerKeyResolutionFailed::class, '404');
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function wellKnownUrls(): iterable
    {
        yield 'origin only' => ['https://example.com', 'https://example.com/.well-known/jwt-vc-issuer'];

        yield 'with path' => [
            'https://example.com/tenant/1234',
            'https://example.com/.well-known/jwt-vc-issuer/tenant/1234',
        ];

        yield 'trailing slash removed' => [
            'https://example.com/tenant/',
            'https://example.com/.well-known/jwt-vc-issuer/tenant',
        ];

        yield 'with port' => ['https://example.com:8443', 'https://example.com:8443/.well-known/jwt-vc-issuer'];
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidIssuers(): iterable
    {
        yield 'http' => ['http://example.com'];

        yield 'query' => ['https://example.com?a=b'];

        yield 'fragment' => ['https://example.com#frag'];

        yield 'no host' => ['urn:example:issuer'];
    }

    /**
     * A PSR-18 stub serving canned JSON per URL (404 otherwise).
     *
     * @param array<string, array<string, mixed>> $responses
     */
    private function httpClient(array $responses): ClientInterface
    {
        $client = $this->createMock(ClientInterface::class);
        $client->method('sendRequest')->willReturnCallback(
            static function (RequestInterface $request) use ($responses): Response {
                $url = (string) $request->getUri();

                if (! isset($responses[$url])) {
                    return new Response(404);
                }

                return new Response(
                    200,
                    ['Content-Type' => 'application/json'],
                    (string) json_encode($responses[$url]),
                );
            },
        );

        return $client;
    }
}
