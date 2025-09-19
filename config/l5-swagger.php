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
            // Scan OpenApi first so component schemas are discovered before controllers reference them
            base_path('app/OpenApi'),
            // Then controllers
            base_path('app/Http'),
            // Then DTOs (schema classes like UserProfile, Tokens)
            base_path('app/DTO'),
        ]
    ]
];
