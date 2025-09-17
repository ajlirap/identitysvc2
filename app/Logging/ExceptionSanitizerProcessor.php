<?php

namespace App\Logging;

use Monolog\LogRecord;

class ExceptionSanitizerProcessor
{
    public function __invoke(LogRecord $record): LogRecord
    {
        $context = $record->context ?? [];

        if (isset($context['exception'])) {
            // Replace exception object/string with a minimal, trace-free structure
            $ex = $context['exception'];
            $context['exception'] = [];

            // Optionally preserve lightweight info without traces
            if ($ex instanceof \Throwable) {
                $context['exception'] = [
                    'class' => $ex::class,
                    'code' => $ex->getCode(),
                    'message' => $ex->getMessage(),
                ];
            }

            return $record->with(context: $context);
        }

        return $record;
    }
}

