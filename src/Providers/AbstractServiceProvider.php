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

use Namshi\JOSE\JWS;
use Anton\JWTAuth\JWT;
use Anton\JWTAuth\Factory;
use Anton\JWTAuth\JWTAuth;
use Anton\JWTAuth\Manager;
use Anton\JWTAuth\JWTGuard;
use Anton\JWTAuth\Blacklist;
use Lcobucci\JWT\Parser as JWTParser;
use Anton\JWTAuth\Http\Parser\Parser;
use Anton\JWTAuth\Http\Parser\Cookies;
use Illuminate\Support\ServiceProvider;
use Lcobucci\JWT\Builder as JWTBuilder;
use Anton\JWTAuth\Providers\JWT\Namshi;
use Anton\JWTAuth\Http\Middleware\Check;
use Anton\JWTAuth\Providers\JWT\Lcobucci;
use Anton\JWTAuth\Http\Parser\AuthHeaders;
use Anton\JWTAuth\Http\Parser\InputSource;
use Anton\JWTAuth\Http\Parser\QueryString;
use Anton\JWTAuth\Http\Parser\RouteParams;
use Anton\JWTAuth\Contracts\Providers\Auth;
use Anton\JWTAuth\Contracts\Providers\Storage;
use Anton\JWTAuth\Validators\PayloadValidator;
use Anton\JWTAuth\Http\Middleware\Authenticate;
use Anton\JWTAuth\Http\Middleware\RefreshToken;
use Anton\JWTAuth\Claims\Factory as ClaimFactory;
use Anton\JWTAuth\Console\JWTGenerateSecretCommand;
use Anton\JWTAuth\Http\Middleware\AuthenticateAndRenew;
use Anton\JWTAuth\Contracts\Providers\JWT as JWTContract;

abstract class AbstractServiceProvider extends ServiceProvider
{
    /**
     * The middleware aliases.
     *
     * @var array
     */
    protected $middlewareAliases = [
        'jwt.auth' => Authenticate::class,
        'jwt.check' => Check::class,
        'jwt.refresh' => RefreshToken::class,
        'jwt.renew' => AuthenticateAndRenew::class,
    ];

    /**
     * Boot the service provider.
     */
    abstract public function boot();

    /**
     * Register the service provider.
     */
    public function register()
    {
        $this->registerAliases();

        $this->registerJWTProvider();
        $this->registerAuthProvider();
        $this->registerStorageProvider();
        $this->registerJWTBlacklist();

        $this->registerManager();
        $this->registerTokenParser();

        $this->registerJWT();
        $this->registerJWTAuth();
        $this->registerPayloadValidator();
        $this->registerClaimFactory();
        $this->registerPayloadFactory();
        $this->registerJWTCommand();

        $this->commands('anton.jwt.secret');
    }

    /**
     * Extend Laravel's Auth.
     */
    protected function extendAuthGuard()
    {
        $this->app['auth']->extend('jwt', function ($app, $name, array $config) {
            $guard = new JWTGuard(
                $app['anton.jwt'],
                $app['auth']->createUserProvider($config['provider']),
                $app['request']
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }

    /**
     * Bind some aliases.
     */
    protected function registerAliases()
    {
        $this->app->alias('anton.jwt', JWT::class);
        $this->app->alias('anton.jwt.auth', JWTAuth::class);
        $this->app->alias('anton.jwt.provider.jwt', JWTContract::class);
        $this->app->alias('anton.jwt.provider.jwt.namshi', Namshi::class);
        $this->app->alias('anton.jwt.provider.jwt.lcobucci', Lcobucci::class);
        $this->app->alias('anton.jwt.provider.auth', Auth::class);
        $this->app->alias('anton.jwt.provider.storage', Storage::class);
        $this->app->alias('anton.jwt.manager', Manager::class);
        $this->app->alias('anton.jwt.blacklist', Blacklist::class);
        $this->app->alias('anton.jwt.payload.factory', Factory::class);
        $this->app->alias('anton.jwt.validators.payload', PayloadValidator::class);
    }

    /**
     * Register the bindings for the JSON Web Token provider.
     */
    protected function registerJWTProvider()
    {
        $this->registerNamshiProvider();
        $this->registerLcobucciProvider();

        $this->app->singleton('anton.jwt.provider.jwt', function ($app) {
            return $this->getConfigInstance('providers.jwt');
        });
    }

    /**
     * Register the bindings for the Lcobucci JWT provider.
     */
    protected function registerNamshiProvider()
    {
        $this->app->singleton('anton.jwt.provider.jwt.namshi', function ($app) {
            return new Namshi(
                new JWS(['typ' => 'JWT', 'alg' => $this->config('algo')]),
                $this->config('secret'),
                $this->config('algo'),
                $this->config('keys')
            );
        });
    }

    /**
     * Register the bindings for the Lcobucci JWT provider.
     */
    protected function registerLcobucciProvider()
    {
        $this->app->singleton('anton.jwt.provider.jwt.lcobucci', function ($app) {
            return new Lcobucci(
                new JWTBuilder(),
                new JWTParser(),
                $this->config('secret'),
                $this->config('algo'),
                $this->config('keys')
            );
        });
    }

    /**
     * Register the bindings for the Auth provider.
     */
    protected function registerAuthProvider()
    {
        $this->app->singleton('anton.jwt.provider.auth', function () {
            return $this->getConfigInstance('providers.auth');
        });
    }

    /**
     * Register the bindings for the Storage provider.
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton('anton.jwt.provider.storage', function () {
            return $this->getConfigInstance('providers.storage');
        });
    }

    /**
     * Register the bindings for the JWT Manager.
     */
    protected function registerManager()
    {
        $this->app->singleton('anton.jwt.manager', function ($app) {
            $instance = new Manager(
                $app['anton.jwt.provider.jwt'],
                $app['anton.jwt.blacklist'],
                $app['anton.jwt.payload.factory']
            );

            return $instance->setBlacklistEnabled((bool) $this->config('blacklist_enabled'))
                            ->setPersistentClaims($this->config('persistent_claims'));
        });
    }

    /**
     * Register the bindings for the Token Parser.
     */
    protected function registerTokenParser()
    {
        $this->app->singleton('anton.jwt.parser', function ($app) {
            $parser = new Parser(
                $app['request'],
                [
                    new AuthHeaders(),
                    new QueryString(),
                    new InputSource(),
                    new RouteParams(),
                    new Cookies($this->config('decrypt_cookies')),
                ]
            );

            $app->refresh('request', $parser, 'setRequest');

            return $parser;
        });
    }

    /**
     * Register the bindings for the main JWT class.
     */
    protected function registerJWT()
    {
        $this->app->singleton('anton.jwt', function ($app) {
            return (new JWT(
                $app['anton.jwt.manager'],
                $app['anton.jwt.parser']
            ))->lockSubject($this->config('lock_subject'));
        });
    }

    /**
     * Register the bindings for the main JWTAuth class.
     */
    protected function registerJWTAuth()
    {
        $this->app->singleton('anton.jwt.auth', function ($app) {
            return (new JWTAuth(
                $app['anton.jwt.manager'],
                $app['anton.jwt.provider.auth'],
                $app['anton.jwt.parser']
            ))->lockSubject($this->config('lock_subject'));
        });
    }

    /**
     * Register the bindings for the Blacklist.
     */
    protected function registerJWTBlacklist()
    {
        $this->app->singleton('anton.jwt.blacklist', function ($app) {
            $instance = new Blacklist($app['anton.jwt.provider.storage']);

            return $instance->setGracePeriod($this->config('blacklist_grace_period'))
                            ->setRefreshTTL($this->config('refresh_ttl'));
        });
    }

    /**
     * Register the bindings for the payload validator.
     */
    protected function registerPayloadValidator()
    {
        $this->app->singleton('anton.jwt.validators.payload', function () {
            return (new PayloadValidator())
                ->setRefreshTTL($this->config('refresh_ttl'))
                ->setRequiredClaims($this->config('required_claims'));
        });
    }

    /**
     * Register the bindings for the Claim Factory.
     */
    protected function registerClaimFactory()
    {
        $this->app->singleton('anton.jwt.claim.factory', function ($app) {
            $factory = new ClaimFactory($app['request']);
            $app->refresh('request', $factory, 'setRequest');

            return $factory->setTTL($this->config('ttl'))
                           ->setLeeway($this->config('leeway'));
        });
    }

    /**
     * Register the bindings for the Payload Factory.
     */
    protected function registerPayloadFactory()
    {
        $this->app->singleton('anton.jwt.payload.factory', function ($app) {
            return new Factory(
                $app['anton.jwt.claim.factory'],
                $app['anton.jwt.validators.payload']
            );
        });
    }

    /**
     * Register the Artisan command.
     */
    protected function registerJWTCommand()
    {
        $this->app->singleton('anton.jwt.secret', function () {
            return new JWTGenerateSecretCommand();
        });
    }

    /**
     * Helper to get the config values.
     *
     * @param string $key
     * @param string $default
     *
     * @return mixed
     */
    protected function config($key, $default = null)
    {
        return config("jwt.$key", $default);
    }

    /**
     * Get an instantiable configuration instance.
     *
     * @param string $key
     *
     * @return mixed
     */
    protected function getConfigInstance($key)
    {
        $instance = $this->config($key);

        if (is_string($instance)) {
            return $this->app->make($instance);
        }

        return $instance;
    }
}
