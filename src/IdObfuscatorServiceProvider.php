<?php

namespace Foziluff\IdObfuscator;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\ServiceProvider;
use Foziluff\IdObfuscator\Middleware\ObfuscateIds;

class IdObfuscatorServiceProvider extends ServiceProvider
{
    public function register()
    {
        //
    }

    public function boot(Kernel $kernel)
    {
        $kernel->pushMiddleware(ObfuscateIds::class);
        $this->app->make(ObfuscateIds::class);
    }
}
