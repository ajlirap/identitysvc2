<?php

namespace App\Support\B2C;

use Illuminate\Support\Facades\Http;

class GraphClient
{
    private function discoverTokenEndpoint(): string
    {
        $tenant = (string) (config('identity.b2c.graph_tenant') ?: config('identity.b2c.tenant'));
        if ($tenant === '') return '';
        try {
            $url = "https://login.microsoftonline.com/{$tenant}/.well-known/openid-configuration";
            $conf = Http::get($url)->throw()->json();
            return (string) ($conf['token_endpoint'] ?? '');
        } catch (\Throwable $e) {
            return '';
        }
    }

    public function accessToken(): string
    {
        $tenant = (string) (config('identity.b2c.graph_tenant') ?: config('identity.b2c.tenant'));
        $endpoint = (string) (config('identity.b2c.graph_token_endpoint')
            ?: $this->discoverTokenEndpoint()
            ?: "https://login.microsoftonline.com/{$tenant}/oauth2/v2.0/token");

        $clientId = (string) config('identity.b2c.graph_client_id');
        $clientSecret = (string) config('identity.b2c.graph_client_secret');
        $configuredScope = (string) config('identity.b2c.graph_scope');

        $isV1 = str_contains($endpoint, '/oauth2/token') && !str_contains($endpoint, '/oauth2/v2.0/');
        $form = [
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ];
        if ($isV1) {
            $resource = $configuredScope;
            if ($resource === '' || str_ends_with($resource, '/.default')) {
                $resource = 'https://graph.microsoft.com';
            } else {
                $resource = rtrim(preg_replace('#/\\.default$#', '', $resource) ?: $resource, '/');
            }
            $form['resource'] = $resource;
        } else {
            $scope = $configuredScope !== '' ? $configuredScope : 'https://graph.microsoft.com/.default';
            $form['scope'] = $scope;
        }

        $resp = Http::asForm()->post($endpoint, $form)->throw()->json();
        return (string) ($resp['access_token'] ?? '');
    }

    public function get(string $url, array $query = [])
    {
        $t = $this->accessToken();
        return Http::withToken($t)->get($url, $query)->throw();
    }

    public function post(string $url, array $body = [])
    {
        $t = $this->accessToken();
        return Http::withToken($t)->post($url, $body)->throw();
    }

    public function patch(string $url, array $body = [])
    {
        $t = $this->accessToken();
        return Http::withToken($t)->patch($url, $body)->throw();
    }

    public function delete(string $url)
    {
        $t = $this->accessToken();
        return Http::withToken($t)->delete($url)->throw();
    }
}

