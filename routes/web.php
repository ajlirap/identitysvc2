<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

// Swagger UI for API docs: redirect to L5-Swagger UI
Route::get('/api/docs', function () {
    return redirect('/api/documentation');
});
