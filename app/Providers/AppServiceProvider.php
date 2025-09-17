<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Psr\Http\Message\RequestInterface;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;

use App\Auth\NullUserProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Register a no-op user provider to satisfy session guard wiring
        Auth::provider('null', function ($app, array $config) {
            return new NullUserProvider();
        });

        // Public endpoint rate limits
        RateLimiter::for('validate-email', function (Request $request) {
            $email = strtolower((string) $request->input('email', ''));
            return [
                // Per-IP and per-email key to deter abuse and enumeration attempts
                Limit::perMinute(30)->by($request->ip()),
                Limit::perMinute(60)->by('email:'.$email),
            ];
        });

        RateLimiter::for('check-active', function (Request $request) {
            $email = strtolower((string) $request->input('email', ''));
            return [
                Limit::perMinute(20)->by($request->ip()),
                Limit::perMinute(40)->by('email:'.$email),
            ];
        });

        // Propagate tracing and correlation headers on all outbound Http:: calls
        Http::globalRequestMiddleware(function (RequestInterface $request) {
            $tcfg = config('identity.tracing', []);
            $corrHeader = $tcfg['correlation_id_header'] ?? 'X-Correlation-Id';
            $reqHeader  = $tcfg['request_id_header'] ?? 'X-Request-Id';
            $tpHeader   = $tcfg['traceparent_header'] ?? 'traceparent';
            $tsHeader   = $tcfg['tracestate_header'] ?? 'tracestate';

            $corr = app()->bound('correlation_id') ? (string) app('correlation_id') : null;
            $req  = app()->bound('request_id') ? (string) app('request_id') : null;
            $traceId = app()->bound('trace_id') ? (string) app('trace_id') : bin2hex(random_bytes(16));
            $spanId  = app()->bound('span_id') ? (string) app('span_id') : bin2hex(random_bytes(8));
            $traceparent = sprintf('00-%s-%s-01', $traceId, $spanId);

            $headers = [ $tpHeader => $traceparent ];
            if ($corr) { $headers[$corrHeader] = $corr; }
            if ($req)  { $headers[$reqHeader] = $req; }
            if (app()->bound('tracestate')) { $headers[$tsHeader] = (string) app('tracestate'); }

            foreach ($headers as $key => $value) {
                if ($value !== null && $value !== '') {
                    $request = $request->withHeader($key, $value);
                }
            }
            return $request;
        });
    }
}
