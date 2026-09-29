<?php

namespace Foziluff\IdObfuscator;

use Foziluff\IdObfuscator\Middleware\ObfuscateIds;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\ServiceProvider;

class IdObfuscatorServiceProvider extends ServiceProvider
{
    public function register()
    {
        //
    }

    public function boot(Kernel $kernel)
    {
        $kernel->pushMiddleware(ObfuscateIds::class);
        app(ObfuscateIds::class);
    }
}
