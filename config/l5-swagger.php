<?php
return [

    /*
    |--------------------------------------------------------------------------
    | Swagger API Docs Configuration
    |--------------------------------------------------------------------------
    |
    | This file is for configuring the settings for the Swagger API documentation.
    | You can customize various aspects of the generated documentation here.
    |
    */
    'paths' => [
        'annotations' => [
            base_path('app/Http/Controllers'),
            base_path('app/OpenApi'), // Add this line to include the OpenApi directory
        ]
    ]
];
