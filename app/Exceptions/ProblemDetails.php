<?php

namespace App\Exceptions;

use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

class ProblemDetails
{
    public static function make(
        int $status,
        ?string $title = null,
        ?string $detail = null,
        ?string $type = null,
        ?string $instance = null,
        array $extensions = []
    ): array {
        $payload = [
            'type' => $type ?: 'about:blank',
            'title' => $title ?: (SymfonyResponse::$statusTexts[$status] ?? 'Error'),
            'status' => $status,
        ];
        if ($detail !== null) {
            $payload['detail'] = $detail;
        }
        if ($instance !== null) {
            $payload['instance'] = $instance;
        }
        // Merge any RFC7807-compatible extensions (e.g., errors, trace_id)
        foreach ($extensions as $k => $v) {
            if (!Arr::has($payload, $k)) {
                $payload[$k] = $v;
            }
        }
        return $payload;
    }

    public static function fromThrowable(\Throwable $e, Request $req, ?int $overrideStatus = null, array $extensions = []): array
    {
        $status = $overrideStatus;
        if ($status === null) {
            $status = $e instanceof HttpExceptionInterface ? $e->getStatusCode() : 500;
        }

        $title = SymfonyResponse::$statusTexts[$status] ?? 'Error';
        $detail = config('app.debug') ? $e->getMessage() : null;

        return self::make(
            status: $status,
            title: $title,
            detail: $detail,
            type: 'about:blank',
            instance: $req->getRequestUri(),
            extensions: $extensions
        );
    }
}

