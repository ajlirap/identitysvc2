<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        // Middleware aliases
        $middleware->alias([
            'verify.jwt' => \App\Http\Middleware\VerifyJwt::class,
        ]);

        // Correlation/Trace IDs early in the chain
        $middleware->prependToGroup('api', \App\Http\Middleware\CorrelationId::class);
        $middleware->prependToGroup('web', \App\Http\Middleware\CorrelationId::class);

        // Request/response logging on API routes by default
        $middleware->appendToGroup('api', \App\Http\Middleware\RequestResponseLogger::class);

        if (env('LOG_HTTP_ALL_ROUTES', false)) {
            $middleware->appendToGroup('web', \App\Http\Middleware\RequestResponseLogger::class);
        }
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        // Do not report expected upstream 4xx client errors to reduce noise
        $exceptions->report(function (Illuminate\Http\Client\RequestException $e) {
            if (isset($e->response)) {
                try { $status = $e->response->status(); } catch (\Throwable) { $status = null; }
                if ($status !== null && $status < 500) {
                    return false; // skip reporting
                }
            }
            return null; // default reporting
        });
        $exceptions->report(function (\GuzzleHttp\Exception\RequestException $e) {
            if ($e->hasResponse()) {
                try { $status = $e->getResponse()->getStatusCode(); } catch (\Throwable) { $status = null; }
                if ($status !== null && $status < 500) {
                    return false;
                }
            }
            return null;
        });
        // RFC 7807 Problem Details for API/JSON requests
        $exceptions->render(function (\Throwable $e, Illuminate\Http\Request $request) {
            $acceptsProblemJson = str_contains((string) $request->header('accept'), 'application/problem+json');
            $wantsJson = $request->expectsJson() || $request->is('api/*') || $acceptsProblemJson;
            if (!$wantsJson) {
                return null; // default HTML rendering
            }

            $status = $e instanceof Symfony\Component\HttpKernel\Exception\HttpExceptionInterface
                ? $e->getStatusCode()
                : 500;

            $extensions = [];
            // Map upstream HTTP client errors to Problem Details
            if ($e instanceof Illuminate\Http\Client\RequestException && isset($e->response)) {
                $resp = $e->response; // Illuminate\Http\Client\Response
                try { $status = $resp->status() ?: $status; } catch (\Throwable) {}
                try {
                    $data = $resp->json();
                    if (is_array($data)) { $extensions['upstream'] = $data; }
                } catch (\Throwable) {
                    try { $raw = $resp->body(); $extensions['upstream'] = ['raw' => $raw]; } catch (\Throwable) {}
                }
            } elseif ($e instanceof \GuzzleHttp\Exception\RequestException && $e->hasResponse()) {
                $g = $e->getResponse(); // Psr Response
                try { $status = $g->getStatusCode() ?: $status; } catch (\Throwable) {}
                try {
                    $raw = (string) $g->getBody();
                    $json = json_decode($raw, true);
                    $extensions['upstream'] = is_array($json) ? $json : ['raw' => $raw];
                } catch (\Throwable) {}
            }

            if ($e instanceof Illuminate\Validation\ValidationException) {
                $status = 422;
                $problem = App\Exceptions\ProblemDetails::make(
                    status: $status,
                    title: 'Unprocessable Entity',
                    detail: config('app.debug') ? $e->getMessage() : null,
                    type: 'about:blank',
                    instance: $request->getRequestUri(),
                    extensions: [ 'errors' => $e->errors() ]
                );
                return response()->json($problem, $status)->header('Content-Type', 'application/problem+json');
            }

            $problem = App\Exceptions\ProblemDetails::fromThrowable($e, $request, $status, $extensions);
            return response()->json($problem, $status)->header('Content-Type', 'application/problem+json');
        });
    })->create();
