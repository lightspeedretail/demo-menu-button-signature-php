<?php
declare(strict_types=1);

use Firebase\JWT\CachedKeySet;
use Firebase\JWT\Key;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;
use League\Uri\Uri;
use Phpfastcache\CacheManager;

require_once('vendor/autoload.php');

const LIGHTSPEED_JWKS_ENDPOINT = 'https://cloud.lightspeedapp.com/.well-known/jwks';

// Rebuild the request URL
$requestUrl = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on')  ? 'https://' : 'http://'
    . $_SERVER['HTTP_HOST']
    // ensure the path starts with a slash
    . '/' . ltrim($_SERVER['REQUEST_URI'], '/');

function validateWebhookUri(string $uri): bool {
    // Apply lossless URI normalization, according to RFC-3986
    // See https://en.wikipedia.org/wiki/URI_normalization
    $uri = Uri::new($uri);

    // validate required query parameters are present
    parse_str((string)$uri->getQuery(), $queryParams);
    if (!isset($queryParams['signature'])
        || !isset($queryParams['exp'])
        || !isset($queryParams['kid'])
        || !isset($queryParams['alg'])
    ) {
        throw new Exception('Bad Request. Required query parameters are missing.');
    }
    // validate that the signature has not expired
    if ($queryParams['exp'] < time()) {
        throw new Exception('Bad Request. Request signature has expired.');
    }

    // Validate the signature matches the request contents to ensure that the request was initiated by Lightspeed.
    // This can prevent request forgery attacks against your application.

    // extract the signature and remove it from the query
    // The signature is url-safe base64 encoded (RFC-4648), convert to binary
    $signature = (string)$queryParams['signature'];
    unset($queryParams['signature']);
    try {
        $decodedSignature = sodium_base642bin($signature, SODIUM_BASE64_VARIANT_URLSAFE);
    } catch (SodiumException $e) {
        throw new Exception('Bad Request. Request signature could not be decoded. Error:' . $e->getMessage(), 0, $e);
    }

    // sort the remaining query parameters alphabetically, in case the server does not preserve the order
    ksort($queryParams);
    // Rebuild the URI without the signature
    $urlWithoutSignature = $uri->withQuery(http_build_query($queryParams))->toString();

    // Fetch and cache Lightspeed's public key set, then return the specific key needed to
    // verify this particular request in RSA PEM format
    $publicKeyPem = fetchLightspeedPublicKeyForKeyId($queryParams['kid'])->getKeyMaterial();
    // Verify the RS256 signature using the public key provided by Lightspeed
    $signatureMatches = 1 === openssl_verify(
        $urlWithoutSignature,
        $decodedSignature,
        $publicKeyPem,
        OPENSSL_ALGO_SHA256
    );

    if (!$signatureMatches) {
        throw new Exception('Bad Request. Request signature could not be verified. Error: ' . openssl_error_string());
    };
    return true;
}

function fetchLightspeedPublicKeyForKeyId(string $keyId): Key
{
    // Create an HTTP client (can be any PSR-7 compatible HTTP client)
    $httpClient = new Client();

    // Create an HTTP request factory (can be any PSR-17 compatible HTTP request factory)
    $httpFactory = new HttpFactory();

    // Create a cache item pool (can be any PSR-6 compatible cache item pool)
    $cacheItemPool = CacheManager::getInstance('files');

    $keySet = new CachedKeySet(
        LIGHTSPEED_JWKS_ENDPOINT,
        $httpClient,
        $httpFactory,
        $cacheItemPool,
        60 * 60, // Cache for 1 hour
    );

    return $keySet->offsetGet($keyId);
}

// test whether the request is valid
echo $requestUrl, "<br><br>";
try {
    validateWebhookUri($requestUrl);
    echo 'Valid Request';
} catch (Exception $e) {
    http_response_code(400);
    echo $e->getMessage();
}