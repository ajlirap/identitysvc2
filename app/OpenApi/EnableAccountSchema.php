<?php

namespace App\OpenApi;

/**
 * @OA\Schema(
 *   schema="GraphAccountEnableRequest",
 *   type="object",
 *   required={"accountEnable"},
 *   @OA\Property(
 *     property="accountEnable",
 *     type="boolean",
 *     description="Set false to disable the user",
 *     example=false
 *   )
 * )
 */
final class EnableAccountSchema {}

