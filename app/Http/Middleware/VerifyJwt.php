<?php

namespace App\Http\Middleware;

use App\Security\JwtValidator;
use App\Support\ProviderFactory;
use Closure;
use Illuminate\Http\Request;

class VerifyJwt
{
    public function __construct(private JwtValidator $validator) {}

    public function handle(Request $request, Closure $next)
    {
        $auth = $request->bearerToken();
        if (!$auth) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }
        $idp = ProviderFactory::identity();
        $claims = $this->validator->validate(
            $auth,
            $idp->issuer(),
            config('identity.common.audience'),
            $idp->jwksUri(),
            (int) config('identity.common.leeway')
        );
        $request->attributes->set('token_claims', $claims);
        return $next($request);
    }
}

