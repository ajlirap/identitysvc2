<?php

namespace App\Logging;

use Monolog\LogRecord;

class CorrelationProcessor
{
    public function __invoke(LogRecord $record): LogRecord
    {
        $context = $record->context ?? [];
        $extra = $record->extra ?? [];

        $corr = $context['correlation_id'] ?? $extra['correlation_id'] ?? null;
        $req = $context['request_id'] ?? $extra['request_id'] ?? null;
        $trace = $context['trace_id'] ?? $extra['trace_id'] ?? (app()->bound('trace_id') ? app('trace_id') : null);
        $span = $context['span_id'] ?? $extra['span_id'] ?? (app()->bound('span_id') ? app('span_id') : null);

        $extra['correlation_id'] = $corr;
        $extra['request_id'] = $req;
        $extra['trace_id'] = $trace;
        $extra['span_id'] = $span;
        $extra['env'] = app()->environment();

        // Add short level code
        $level = strtoupper((string) $record->level->getName());
        $map = [
            'DEBUG' => 'DBG', 'INFO' => 'INF', 'NOTICE' => 'NOT', 'WARNING' => 'WRN',
            'ERROR' => 'ERR', 'CRITICAL' => 'CRT', 'ALERT' => 'ALR', 'EMERGENCY' => 'EMG',
        ];
        $extra['level_short'] = $map[$level] ?? $level;

        return $record->with(extra: $extra);
    }
}
