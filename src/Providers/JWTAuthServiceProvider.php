<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Anton <Anton148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Anton\JWTAuth\Providers;

use Anton\JWTAuth\JWTAuth;
use Anton\JWTAuth\Blacklist;
use Anton\JWTAuth\JWTManager;
use Anton\JWTAuth\Claims\Factory;
use Anton\JWTAuth\PayloadFactory;
use Illuminate\Support\ServiceProvider;
use Anton\JWTAuth\Commands\JWTGenerateCommand;
use Anton\JWTAuth\Validators\PayloadValidator;

class JWTAuthServiceProvider extends ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Boot the service provider.
     */
    public function boot()
    {
        $this->publishes([
            __DIR__.'/../config/config.php' => config_path('jwt.php'),
        ], 'config');

        $this->bootBindings();

        $this->commands('Anton.jwt.generate');
    }

    /**
     * Bind some Interfaces and implementations.
     */
    protected function bootBindings()
    {
        $this->app->singleton('Anton\JWTAuth\JWTAuth', function ($app) {
            return $app['Anton.jwt.auth'];
        });

        $this->app->singleton('Anton\JWTAuth\Providers\User\UserInterface', function ($app) {
            return $app['Anton.jwt.provider.user'];
        });

        $this->app->singleton('Anton\JWTAuth\Providers\JWT\JWTInterface', function ($app) {
            return $app['Anton.jwt.provider.jwt'];
        });

        $this->app->singleton('Anton\JWTAuth\Providers\Auth\AuthInterface', function ($app) {
            return $app['Anton.jwt.provider.auth'];
        });

        $this->app->singleton('Anton\JWTAuth\Providers\Storage\StorageInterface', function ($app) {
            return $app['Anton.jwt.provider.storage'];
        });

        $this->app->singleton('Anton\JWTAuth\JWTManager', function ($app) {
            return $app['Anton.jwt.manager'];
        });

        $this->app->singleton('Anton\JWTAuth\Blacklist', function ($app) {
            return $app['Anton.jwt.blacklist'];
        });

        $this->app->singleton('Anton\JWTAuth\PayloadFactory', function ($app) {
            return $app['Anton.jwt.payload.factory'];
        });

        $this->app->singleton('Anton\JWTAuth\Claims\Factory', function ($app) {
            return $app['Anton.jwt.claim.factory'];
        });

        $this->app->singleton('Anton\JWTAuth\Validators\PayloadValidator', function ($app) {
            return $app['Anton.jwt.validators.payload'];
        });
    }

    /**
     * Register the service provider.
     */
    public function register()
    {
        // register providers
        $this->registerUserProvider();
        $this->registerJWTProvider();
        $this->registerAuthProvider();
        $this->registerStorageProvider();
        $this->registerJWTBlacklist();

        $this->registerClaimFactory();
        $this->registerJWTManager();

        $this->registerJWTAuth();
        $this->registerPayloadValidator();
        $this->registerPayloadFactory();
        $this->registerJWTCommand();

        $this->mergeConfigFrom(__DIR__.'/../config/config.php', 'jwt');
    }

    /**
     * Register the bindings for the User provider.
     */
    protected function registerUserProvider()
    {
        $this->app->singleton('Anton.jwt.provider.user', function ($app) {
            $provider = $this->config('providers.user');
            $model = $app->make($this->config('user'));

            return new $provider($model);
        });
    }

    /**
     * Register the bindings for the JSON Web Token provider.
     */
    protected function registerJWTProvider()
    {
        $this->app->singleton('Anton.jwt.provider.jwt', function ($app) {
            $secret = $this->config('secret');
            $algo = $this->config('algo');
            $provider = $this->config('providers.jwt');

            return new $provider($secret, $algo);
        });
    }

    /**
     * Register the bindings for the Auth provider.
     */
    protected function registerAuthProvider()
    {
        $this->app->singleton('Anton.jwt.provider.auth', function ($app) {
            return $this->getConfigInstance($this->config('providers.auth'));
        });
    }

    /**
     * Register the bindings for the Storage provider.
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton('Anton.jwt.provider.storage', function ($app) {
            return $this->getConfigInstance($this->config('providers.storage'));
        });
    }

    /**
     * Register the bindings for the Payload Factory.
     */
    protected function registerClaimFactory()
    {
        $this->app->singleton('Anton.jwt.claim.factory', function () {
            return new Factory();
        });
    }

    /**
     * Register the bindings for the JWT Manager.
     */
    protected function registerJWTManager()
    {
        $this->app->singleton('Anton.jwt.manager', function ($app) {
            $instance = new JWTManager(
                $app['Anton.jwt.provider.jwt'],
                $app['Anton.jwt.blacklist'],
                $app['Anton.jwt.payload.factory']
            );

            return $instance->setBlacklistEnabled((bool) $this->config('blacklist_enabled'));
        });
    }

    /**
     * Register the bindings for the main JWTAuth class.
     */
    protected function registerJWTAuth()
    {
        $this->app->singleton('Anton.jwt.auth', function ($app) {
            $auth = new JWTAuth(
                $app['Anton.jwt.manager'],
                $app['Anton.jwt.provider.user'],
                $app['Anton.jwt.provider.auth'],
                $app['request']
            );

            return $auth->setIdentifier($this->config('identifier'));
        });
    }

    /**
     * Register the bindings for the main JWTAuth class.
     */
    protected function registerJWTBlacklist()
    {
        $this->app->singleton('Anton.jwt.blacklist', function ($app) {
            $instance = new Blacklist($app['Anton.jwt.provider.storage']);

            return $instance->setRefreshTTL($this->config('refresh_ttl'));
        });
    }

    /**
     * Register the bindings for the payload validator.
     */
    protected function registerPayloadValidator()
    {
        $this->app->singleton('Anton.jwt.validators.payload', function () {
            return with(new PayloadValidator())->setRefreshTTL($this->config('refresh_ttl'))->setRequiredClaims($this->config('required_claims'));
        });
    }

    /**
     * Register the bindings for the Payload Factory.
     */
    protected function registerPayloadFactory()
    {
        $this->app->singleton('Anton.jwt.payload.factory', function ($app) {
            $factory = new PayloadFactory($app['Anton.jwt.claim.factory'], $app['request'], $app['Anton.jwt.validators.payload']);

            return $factory->setTTL($this->config('ttl'));
        });
    }

    /**
     * Register the Artisan command.
     */
    protected function registerJWTCommand()
    {
        $this->app->singleton('Anton.jwt.generate', function () {
            return new JWTGenerateCommand();
        });
    }

    /**
     * Helper to get the config values.
     *
     * @param string $key
     *
     * @return string
     */
    protected function config($key, $default = null)
    {
        return config("jwt.$key", $default);
    }

    /**
     * Get an instantiable configuration instance. Pinched from dingo/api :).
     *
     * @param mixed $instance
     *
     * @return object
     */
    protected function getConfigInstance($instance)
    {
        if (is_callable($instance)) {
            return call_user_func($instance, $this->app);
        } elseif (is_string($instance)) {
            return $this->app->make($instance);
        }

        return $instance;
    }
}
