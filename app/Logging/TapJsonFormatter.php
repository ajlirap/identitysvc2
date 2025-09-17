<?php

namespace App\Logging;

use Illuminate\Log\Logger as IlluminateLogger;
use Monolog\Formatter\JsonFormatter;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\HandlerInterface;
use Monolog\Logger as MonologLogger;

class TapJsonFormatter
{
    public function __invoke($logger): void
    {
        // Resolve the underlying Monolog logger regardless of wrapper type
        $monolog = $logger instanceof IlluminateLogger ? $logger->getLogger() : $logger;

        if ($monolog instanceof MonologLogger) {
            foreach ($monolog->getHandlers() as $handler) {
                $this->configureHandler($handler);
                // Processors: correlation + exception sanitization (no stack traces)
                $handler->pushProcessor(new CorrelationProcessor());
                $handler->pushProcessor(new ExceptionSanitizerProcessor());
            }
        }
    }

    private function configureHandler(HandlerInterface $handler): void
    {
        $format = strtolower((string) env('LOG_FORMAT', 'json'));
        if ($format === 'line') {
            $dateFormat = 'Y-m-d H:i:s.v P';
            $output = '[%datetime%|%extra.level_short%|%extra.correlation_id% (%extra.request_id%) %extra.trace_id%/%extra.span_id%|%extra.env%] %message% %context%' . PHP_EOL;
            // includeStacktraces=false to avoid multiline [stacktrace] blocks
            $formatter = new LineFormatter($output, $dateFormat, true, true, false);
            $handler->setFormatter($formatter);
            return;
        }

        // Default JSON formatter (structured logs)
        $formatter = new JsonFormatter(JsonFormatter::BATCH_MODE_JSON, true);
        $handler->setFormatter($formatter);
    }
}
