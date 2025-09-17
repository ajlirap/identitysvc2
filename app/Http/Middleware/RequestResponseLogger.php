<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class RequestResponseLogger
{
    public function handle(Request $request, Closure $next)
    {
        $logAll = filter_var(env('LOG_HTTP_ALL_ROUTES', false), FILTER_VALIDATE_BOOL);
        if (!$logAll && !$request->is('api/*')) {
            return $next($request);
        }

        // Prefer IDs established by CorrelationId middleware; fallback to headers/uuid
        $correlationId = app()->bound('correlation_id') ? (string) app('correlation_id') : ((string) ($request->headers->get('X-Correlation-Id') ?: Str::uuid()));
        $requestId = app()->bound('request_id') ? (string) app('request_id') : (string) Str::uuid();
        $traceId = app()->bound('trace_id') ? (string) app('trace_id') : null;
        $spanId = app()->bound('span_id') ? (string) app('span_id') : null;

        $start = microtime(true);

        $headers = $this->safeHeaders($request->headers->all());
        $body = $this->maybeBody($request->getContent());

        Log::channel('http')->info('http.request', [
            'method' => $request->getMethod(),
            'path' => '/'.$request->path(),
            'ip' => $request->ip(),
            'query' => $request->query(),
            'user_agent' => $request->userAgent(),
            'content_type' => $request->headers->get('Content-Type'),
            'content_length' => $request->headers->get('Content-Length'),
            'headers' => $headers,
            'body' => $body,
            // Include correlation IDs in context so formatter can render them
            'correlation_id' => $correlationId,
            'request_id' => $requestId,
            'trace_id' => $traceId,
            'span_id' => $spanId,
        ]);

        $response = $next($request);

        $duration = (int) round((microtime(true) - $start) * 1000);
        $respBody = $this->maybeBody($response->getContent());
        $respLen = $response->headers->get('Content-Length');
        if ($respLen === null) {
            $respLen = $response->getContent() !== null ? strlen((string) $response->getContent()) : 0;
        }

        $response->headers->set('X-Correlation-Id', $correlationId);
        $response->headers->set('X-Request-Id', $requestId);

        Log::channel('http')->info('http.response', [
            'method' => $request->getMethod(),
            'path' => '/'.$request->path(),
            'status' => $response->getStatusCode(),
            'duration_ms' => $duration,
            'response_length' => $respLen,
            'content_type' => $response->headers->get('Content-Type'),
            'body' => $respBody,
            'correlation_id' => $correlationId,
            'request_id' => $requestId,
            'trace_id' => $traceId,
            'span_id' => $spanId,
        ]);

        return $response;
    }

    private function safeHeaders(array $headers): array
    {
        $redact = ['authorization', 'cookie', 'set-cookie', 'x-api-key'];
        foreach ($headers as $k => &$v) {
            $name = strtolower($k);
            if (in_array($name, $redact, true)) {
                $v = ['[REDACTED]'];
            }
        }
        return $headers;
    }

    private function maybeBody(?string $content): ?string
    {
        $logReq = filter_var(env('LOG_HTTP_REQUEST_BODY', false), FILTER_VALIDATE_BOOL);
        $logResp = filter_var(env('LOG_HTTP_RESPONSE_BODY', false), FILTER_VALIDATE_BOOL);
        $max = (int) env('LOG_HTTP_MAX_BODY', 2048);

        // Called for both request & response; decide by presence of server key
        $enabled = $logReq || $logResp;
        if (!$enabled || $content === null || $content === '') {
            return null;
        }
        if (strlen($content) > $max) {
            return substr($content, 0, $max).'...';
        }
        return $content;
    }
}
