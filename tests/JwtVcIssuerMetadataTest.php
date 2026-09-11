<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Tests;

use K2gl\Dsse\Verifier;
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
            self::urlPolicy(),
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
            self::urlPolicy(),
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
            self::urlPolicy(),
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
            self::urlPolicy(),
        );

        // act + assert
        fact(static fn () => $resolver->resolve(self::DRAFT_ISSUER, (object) []))
            ->throws(IssuerKeyResolutionFailed::class);
    }

    public function testHttpErrorIsRejected(): void
    {
        // assert: stub 404s every URL
        $resolver = new JwtVcIssuerMetadata($this->httpClient([]), new Psr17Factory, self::urlPolicy());

        // act + assert
        fact(static fn () => $resolver->resolve(self::DRAFT_ISSUER, (object) []))
            ->throws(IssuerKeyResolutionFailed::class, '404');
    }

    public function testFollowsRedirectsToHttpsUrls(): void
    {
        // arrange
        $resolver = $this->resolverWith([
            self::WELL_KNOWN => new Response(302, ['Location' => 'https://cdn.example.com/issuer-metadata.json']),
            'https://cdn.example.com/issuer-metadata.json' => self::json(self::inlineMetadata()),
        ]);

        // act
        $verifier = $resolver->resolve(self::DRAFT_ISSUER, (object) ['kid' => 'doc-signer-05-25-2022']);

        // assert
        fact($verifier)->instanceOf(Verifier::class);
    }

    public function testJsonWithParametersIsAccepted(): void
    {
        // arrange
        $resolver = $this->resolverWith([
            self::WELL_KNOWN => new Response(200, ['Content-Type' => 'application/json; charset=utf-8'], (string) json_encode(self::inlineMetadata())),
        ]);

        // act + assert
        fact($resolver->resolve(self::DRAFT_ISSUER, (object) []))->instanceOf(Verifier::class);
    }

    #[DataProvider('refusedRetrievals')]
    public function testRefusesRetrievalsOutsideTheSection3Rules(array $responses, string $message): void
    {
        // arrange
        $resolver = $this->resolverWith($responses);

        // act + assert
        fact(static fn () => $resolver->resolve(self::DRAFT_ISSUER, (object) []))
            ->throws(IssuerKeyResolutionFailed::class, $message);
    }

    /**
     * @return array<string, array{array<string, Response>, string}>
     */
    public static function refusedRetrievals(): array
    {
        $metadata = (string) json_encode(self::inlineMetadata());

        return [
            'redirect to http'         => [[self::WELL_KNOWN => new Response(302, ['Location' => 'http://example.com/meta'])], 'not an HTTPS URL'],
            'redirect to loopback'     => [[self::WELL_KNOWN => new Response(302, ['Location' => 'https://127.0.0.1/meta'])], 'internal address 127.0.0.1'],
            'too many redirects'       => [[
                self::WELL_KNOWN => new Response(301, ['Location' => 'https://example.com/a']),
                'https://example.com/a' => new Response(301, ['Location' => 'https://example.com/b']),
                'https://example.com/b' => new Response(301, ['Location' => 'https://example.com/c']),
                'https://example.com/c' => new Response(301, ['Location' => 'https://example.com/d']),
            ], 'exceeded 3 redirects'],
            'redirect without location' => [[self::WELL_KNOWN => new Response(302)], 'HTTP 302'],
            'server error'             => [[self::WELL_KNOWN => new Response(500, ['Content-Type' => 'application/json'], $metadata)], 'HTTP 500'],
            'html instead of json'     => [[self::WELL_KNOWN => new Response(200, ['Content-Type' => 'text/html'], $metadata)], 'Expected application/json'],
            'no content type'          => [[self::WELL_KNOWN => new Response(200, [], $metadata)], 'Expected application/json'],
            'json array'               => [[self::WELL_KNOWN => new Response(200, ['Content-Type' => 'application/json'], '[1]')], 'not a JSON object'],
            'empty 204'                => [[self::WELL_KNOWN => new Response(204, ['Content-Type' => 'application/json'])], 'not a JSON object'],
        ];
    }

    public function testRefusesDocumentsLargerThanTheLimit(): void
    {
        // arrange: a 2 KiB document against a 1 KiB limit
        $padded = self::inlineMetadata() + ['padding' => str_repeat('x', 2048)];
        $resolver = new JwtVcIssuerMetadata(
            $this->httpResponses([self::WELL_KNOWN => self::json($padded)]),
            new Psr17Factory,
            self::urlPolicy(),
            maxBytes: 1024,
        );

        // act + assert
        fact(static fn () => $resolver->resolve(self::DRAFT_ISSUER, (object) []))
            ->throws(IssuerKeyResolutionFailed::class, 'larger than 1024 bytes');
    }

    public function testSendsAnAcceptHeader(): void
    {
        // arrange
        $seen = [];
        $client = $this->createMock(ClientInterface::class);
        $client->method('sendRequest')->willReturnCallback(
            static function (RequestInterface $request) use (&$seen): Response {
                $seen[] = $request->getHeaderLine('Accept');

                return self::json(self::inlineMetadata());
            },
        );
        $resolver = new JwtVcIssuerMetadata($client, new Psr17Factory, self::urlPolicy());

        // act
        $resolver->resolve(self::DRAFT_ISSUER, (object) []);

        // assert
        fact($seen)->is(['application/json']);
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

    private const WELL_KNOWN = 'https://example.com/.well-known/jwt-vc-issuer/issuer';

    /**
     * @return array<string, mixed>
     */
    private static function inlineMetadata(): array
    {
        return [
            'issuer' => self::DRAFT_ISSUER,
            'jwks' => ['keys' => [self::draftIssuerJwk() + ['kid' => 'doc-signer-05-25-2022']]],
        ];
    }

    /**
     * @param array<string, mixed> $document
     */
    private static function json(array $document): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], (string) json_encode($document));
    }

    /**
     * @param array<string, Response> $responses
     */
    private function resolverWith(array $responses): JwtVcIssuerMetadata
    {
        return new JwtVcIssuerMetadata($this->httpResponses($responses), new Psr17Factory, self::urlPolicy());
    }

    /**
     * A PSR-18 stub serving canned responses per URL (404 otherwise).
     *
     * @param array<string, Response> $responses
     */
    private function httpResponses(array $responses): ClientInterface
    {
        $client = $this->createMock(ClientInterface::class);
        $client->method('sendRequest')->willReturnCallback(
            static fn (RequestInterface $request): Response => $responses[(string) $request->getUri()] ?? new Response(404),
        );

        return $client;
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
