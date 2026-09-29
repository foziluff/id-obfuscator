<?php

namespace Foziluff\IdObfuscator\Middleware;

use Closure;
use GuzzleHttp\Psr7\Utils;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Psr\Http\Message\RequestInterface;
use Symfony\Component\HttpFoundation\Response;

class ObfuscateIds
{
    private static ?string $key = null;

    private static bool $httpMacroRegistered = false;

    public function __construct()
    {
        if (! self::$httpMacroRegistered) {
            Http::globalRequestMiddleware($this->outgoingHttpMiddleware());
            self::$httpMacroRegistered = true;
        }
    }

    private static function key(): string
    {
        return self::$key ??= substr(base64_decode(str_replace('base64:', '', config('app.key'))), 0, 16);
    }

    public static function encode(int $id): string
    {
        return bin2hex(openssl_encrypt(pack('J', $id)."\x00\x00\x00\x00\x00\x00\x00\x00", 'aes-128-ecb', self::key(), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING));
    }

    public static function decode(string $hash): ?int
    {
        if (strlen($hash) !== 32 || ! ctype_xdigit($hash)) {
            return null;
        }

        $plain = openssl_decrypt(hex2bin($hash), 'aes-128-ecb', self::key(), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

        if ($plain === false || strlen($plain) !== 16 || substr($plain, 8) !== "\x00\x00\x00\x00\x00\x00\x00\x00") {
            return null;
        }

        return (int) unpack('J', $plain)[1];
    }

    public function outgoingHttpMiddleware(): callable
    {
        return function (RequestInterface $request) {
            if (! env('OBFUSCATE_IDS', false)) {
                return $request;
            }

            return $this->encodeOutgoing($request);
        };
    }

    private function encodeOutgoing(RequestInterface $request): RequestInterface
    {
        $uri = $request->getUri();

        $path = preg_replace_callback('/(?<=\/)(\d+)(?=\/|\?|$)/', function ($m) {
            return self::encode((int) $m[1]);
        }, $uri->getPath());

        $query = $uri->getQuery();
        if (! empty($query)) {
            parse_str($query, $parsedQuery);
            $query = http_build_query(self::encodeData($parsedQuery));
        }

        $request = $request->withUri($uri->withPath($path)->withQuery($query));

        $contentType = $request->getHeaderLine('Content-Type');
        $body = (string) $request->getBody();

        if (! empty($body)) {
            if (str_contains($contentType, 'application/json')) {
                $data = json_decode($body, true);
                if (is_array($data)) {
                    $request = $request->withBody(Utils::streamFor(json_encode(self::encodeData($data))));
                }
            } elseif (str_contains($contentType, 'application/x-www-form-urlencoded')) {
                parse_str($body, $data);
                if (! empty($data)) {
                    $request = $request->withBody(Utils::streamFor(http_build_query(self::encodeData($data))));
                }
            }
        }

        return $request;
    }

    public function handle(Request $request, Closure $next): Response
    {
        if (! env('OBFUSCATE_IDS', false)) {
            return $next($request);
        }

        if ($authHeader = $request->header('Authorization')) {
            if (str_starts_with($authHeader, 'Bearer ')) {
                $token = substr($authHeader, 7);
                if (str_contains($token, '|')) {
                    [$hash, $plainText] = explode('|', $token, 2);
                    if (strlen($hash) === 32) {
                        $realId = self::decode($hash);
                        if ($realId !== null) {
                            $request->headers->set('Authorization', "Bearer {$realId}|{$plainText}");
                            $request->server->set('HTTP_AUTHORIZATION', "Bearer {$realId}|{$plainText}");
                        }
                    }
                }
            }
        }

        $this->decodeIncoming($request);

        $response = $next($request);

        if ($response instanceof JsonResponse) {
            $response->setData(self::encodeData($response->getData(true)));
        }

        return $response;
    }

    private function decodeIncoming(Request $request): void
    {
        $this->rewriteUrl($request);

        if ($query = $request->query->all()) {
            $request->query->replace($this->decodeData($query));
        }

        if ($post = $request->request->all()) {
            $request->request->replace($this->decodeData($post));
        }
    }

    private function decodeData(mixed $value, ?string $key = null): mixed
    {
        if (is_string($value) && $key !== null) {
            if ($this->isIdKey($key) || $key === 'id') {
                return self::decode($value) ?? $value;
            }
            if ($key === 'cursor') {
                return $this->transformCursor($value, 'decode');
            }
        }

        if (is_array($value)) {
            foreach ($value as $k => &$v) {
                $childKey = (string) $k;
                if (is_int($k) && $key !== null) {
                    if ($this->isIdKey($key) || str_ends_with($key, '_ids') || $key === 'ids') {
                        $childKey = 'id';
                    }
                }
                $v = $this->decodeData($v, $childKey);
            }
        }

        return $value;
    }

    private function rewriteUrl(Request $request): void
    {
        $server = $request->server->all();
        $modified = false;

        $replacer = fn (array $m) => ($decoded = self::decode($m[0])) !== null ? (string) $decoded : $m[0];

        foreach (['REQUEST_URI', 'PATH_INFO'] as $serverKey) {
            if (isset($server[$serverKey])) {
                $newVal = preg_replace_callback('/[a-f0-9]{32}/i', $replacer, $server[$serverKey]);
                if ($newVal !== $server[$serverKey]) {
                    $server[$serverKey] = $newVal;
                    $modified = true;
                }
            }
        }

        if ($modified) {
            $request->initialize(
                $request->query->all(),
                $request->request->all(),
                $request->attributes->all(),
                $request->cookies->all(),
                $request->files->all(),
                $server,
                $request->getContent(true)
            );
        }
    }

    public static function encodeData(mixed $value, ?string $key = null): mixed
    {
        if ((is_int($value) || (is_string($value) && ctype_digit($value))) && $key !== null && (self::isIdKey($key) || $key === 'id')) {
            return self::encode((int) $value);
        }

        if (is_string($value) && $key !== null) {
            if (in_array($key, ['token', 'access_token'], true) && preg_match('/^(\d+)\|(.+)$/', $value, $matches)) {
                return self::encode((int) $matches[1]).'|'.$matches[2];
            }

            if (in_array($key, ['next_cursor', 'prev_cursor'], true)) {
                return self::transformCursor($value, 'encode');
            }

            if (in_array($key, ['next_page_url', 'prev_page_url', 'first_page_url', 'last_page_url', 'path', 'url'], true)) {
                return self::encodeUrl($value);
            }
        }

        if (is_array($value)) {
            foreach ($value as $k => &$v) {
                $childKey = (string) $k;
                if (is_int($k) && $key !== null) {
                    if (self::isIdKey($key) || str_ends_with($key, '_ids') || $key === 'ids') {
                        $childKey = 'id';
                    }
                }
                $v = self::encodeData($v, $childKey);
            }
        }

        return $value;
    }

    private static function encodeUrl(string $url): string
    {
        $url = preg_replace_callback('/(?<=\/)(\d+)(?=\/|\?|$)/', function ($m) {
            return self::encode((int) $m[1]);
        }, $url);

        if (! $queryStr = parse_url($url, PHP_URL_QUERY)) {
            return $url;
        }

        parse_str($queryStr, $query);

        if (! isset($query['cursor'])) {
            return $url;
        }

        $query['cursor'] = self::transformCursor($query['cursor'], 'encode');

        return str_replace($queryStr, http_build_query($query), $url);
    }

    private static function transformCursor(string $cursor, string $mode): string
    {
        if (! $decoded = base64_decode(strtr($cursor, '-_', '+/'), true)) {
            return $cursor;
        }

        if (! is_array($params = json_decode($decoded, true))) {
            return $cursor;
        }

        foreach ($params as $k => &$v) {
            if (! self::isIdKey((string) $k)) {
                continue;
            }

            if ($mode === 'encode' && is_int($v)) {
                $v = self::encode($v);
            } elseif ($mode === 'decode' && is_string($v)) {
                if (($real = self::decode($v)) !== null) {
                    $v = $real;
                }
            }
        }

        return rtrim(strtr(base64_encode(json_encode($params)), '+/', '-_'), '=');
    }

    private static function isIdKey(string $key): bool
    {
        return $key === 'id' || str_ends_with($key, '_id');
    }
}
