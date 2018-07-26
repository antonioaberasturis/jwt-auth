<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Anton <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Anton\JWTAuth\Providers;

use Anton\JWTAuth\Http\Parser\AuthHeaders;
use Anton\JWTAuth\Http\Parser\InputSource;
use Anton\JWTAuth\Http\Parser\QueryString;
use Anton\JWTAuth\Http\Parser\LumenRouteParams;

class LumenServiceProvider extends AbstractServiceProvider
{
    /**
     * {@inheritdoc}
     */
    public function boot()
    {
        $this->app->configure('jwt');

        $path = realpath(__DIR__.'/../../config/config.php');
        $this->mergeConfigFrom($path, 'jwt');

        $this->app->routeMiddleware($this->middlewareAliases);

        $this->extendAuthGuard();

        $this->app['anton.jwt.parser']->setChain([
            new AuthHeaders(),
            new QueryString(),
            new InputSource(),
            new LumenRouteParams(),
        ]);
    }
}
