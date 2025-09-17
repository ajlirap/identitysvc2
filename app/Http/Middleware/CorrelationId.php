<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

class CorrelationId
{
    public function handle(Request $request, Closure $next): Response
    {
        $cfg = config('identity.tracing', []);
        $corrHeader = $cfg['correlation_id_header'] ?? 'X-Correlation-Id';
        $reqHeader  = $cfg['request_id_header'] ?? 'X-Request-Id';
        $tpHeader   = $cfg['traceparent_header'] ?? 'traceparent';
        $tsHeader   = $cfg['tracestate_header'] ?? 'tracestate';

        // Correlation and Request IDs
        $correlationId = (string) ($request->headers->get($corrHeader) ?: Str::uuid());
        $requestId     = (string) ($request->headers->get($reqHeader)  ?: Str::uuid());

        // W3C Trace Context (traceparent / tracestate)
        $incomingTp = (string) $request->headers->get($tpHeader, '');
        $incomingTs = (string) $request->headers->get($tsHeader, '');

        [$traceId, $spanId, $parentSpanId, $flags] = $this->parseOrCreateTraceContext($incomingTp);
        if ($incomingTs !== '') {
            app()->instance('tracestate', $incomingTs);
        }

        // Make IDs available app-wide and in logs
        app()->instance('correlation_id', $correlationId);
        app()->instance('request_id', $requestId);
        app()->instance('trace_id', $traceId);
        app()->instance('span_id', $spanId);
        app()->instance('parent_span_id', $parentSpanId);

        Log::withContext([
            'correlation_id' => $correlationId,
            'request_id'     => $requestId,
            'trace_id'       => $traceId,
            'span_id'        => $spanId,
        ]);

        /** @var Response $response */
        $response = $next($request);

        // Propagate headers on response
        $response->headers->set($corrHeader, $correlationId);
        $response->headers->set($reqHeader, $requestId);
        $response->headers->set($tpHeader, $this->buildTraceparent($traceId, $spanId, $flags));
        if ($incomingTs !== '') {
            $response->headers->set($tsHeader, $incomingTs);
        }

        return $response;
    }

    private function parseOrCreateTraceContext(string $traceparent): array
    {
        // Returns [traceId, spanId, parentSpanId, flags]
        $traceId = bin2hex(random_bytes(16)); // 32 hex
        $spanId  = bin2hex(random_bytes(8));  // 16 hex
        $flags   = '01';                      // sampled
        $parent  = null;

        if ($traceparent) {
            // Format: version-traceid-spanid-flags
            $parts = preg_split('/\s*-\s*/', trim($traceparent));
            if (count($parts) >= 4) {
                [$ver, $t, $s, $f] = [$parts[0], $parts[1], $parts[2], $parts[3]];
                $isValid = strlen($t) === 32 && strlen($s) === 16 && ctype_xdigit($t.$s.$f);
                if ($isValid && $t !== str_repeat('0', 32) && $s !== str_repeat('0', 16)) {
                    $traceId = strtolower($t);
                    $parent  = strtolower($s);
                    $flags   = strtolower(substr($f, 0, 2));
                    // New span for this hop
                    $spanId  = bin2hex(random_bytes(8));
                }
            }
        }

        return [$traceId, $spanId, $parent, $flags];
    }

    private function buildTraceparent(string $traceId, string $spanId, string $flags = '01'): string
    {
        $version = '00';
        $flags = substr(strtolower($flags ?: '01'), 0, 2);
        return sprintf('%s-%s-%s-%s', $version, $traceId, $spanId, $flags);
    }
}
