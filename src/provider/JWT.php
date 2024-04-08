<?php


namespace thans\jwt\provider;

use thans\jwt\facade\JWTAuth;
use thans\jwt\parser\AuthHeader;
use thans\jwt\parser\Cookie;
use thans\jwt\parser\Param;
use thans\jwt\exception\JWTException;
use think\App;
use think\Container;
use think\facade\Config;
use think\Request;

class JWT
{
    private $request;

    private $config;

    private $guard;

    public function __construct(Request $request)
    {
        $this->request = $request;
        $config = require __DIR__ . '/../../config/config.php';

        $this->guard = Config::get('jwt.default');
        if (strpos(App::VERSION, '5.') !== 0) {
            $this->config = array_merge($config['guards']['api'], Config::get("jwt.guards.{$this->guard}") ?? []);
        } else {
            $this->config = array_merge($config['guards']['api'], Config::get("jwt.guards.{$this->guard}.") ?? []);
        }
    }

    protected function registerBlacklist()
    {
        Container::getInstance()->make('thans\jwt\Blacklist', [
            new $this->config['blacklist_storage'],
        ])->setRefreshTTL($this->config['refresh_ttl'])->setGracePeriod($this->config['blacklist_grace_period']);
    }


    protected function registerProvider()
    {
        //builder asymmetric keys
        $keys = $this->config['secret']
            ? $this->config['secret']
            : [
                'public' => $this->config['public_key'],
                'private' => $this->config['private_key'],
                'password' => $this->config['password'],
            ];

        // 配置错误
        if (empty($this->config['secret']) && is_null($keys['public'])) {
            throw new JWTException("Invalid SECRET or Invalid Keys");
        }

        Container::getInstance()->make('thans\jwt\provider\JWT\Lcobucci', [
            $this->config['algo'],
            $keys,
        ]);
    }

    protected function registerFactory()
    {
        Container::getInstance()->make('thans\jwt\claim\Factory', [
            new Request(),
            $this->config['ttl'],
            $this->config['refresh_ttl'],
        ]);
    }

    protected function registerPayload()
    {
        Container::getInstance()->make('thans\jwt\Payload', [
            Container::getInstance()->make('thans\jwt\claim\Factory'),
        ]);
    }

    protected function registerManager()
    {
        Container::getInstance()->make('thans\jwt\Manager', [
            $this->guard,
            Container::getInstance()->make('thans\jwt\Blacklist'),
            Container::getInstance()->make('thans\jwt\Payload'),
            Container::getInstance()->make('thans\jwt\provider\JWT\Lcobucci'),
        ]);
    }

    protected function registerJWTAuth()
    {
        $chains = [
            'header' => new AuthHeader(),
            'cookie' => new Cookie(),
            'param' => new Param()
        ];

        $mode = $this->config['token_mode'];
        $setChain = [];

        foreach ($mode as $key => $chain) {
            if (isset($chains[$chain])) {
                $setChain[$key] = $chains[$chain];
            }
        }

        JWTAuth::parser()->setRequest($this->request)->setChain($setChain);
    }

    public function setGuard(string $guard)
    {
        // 删除容器
        Container::getInstance()->delete('thans\jwt\Blacklist');
        Container::getInstance()->delete('thans\jwt\provider\JWT\Lcobucci');
        Container::getInstance()->delete('thans\jwt\claim\Factory');
        Container::getInstance()->delete('thans\jwt\Payload');
        Container::getInstance()->delete('thans\jwt\Manager');
        Container::getInstance()->delete('thans\jwt\JWTAuth');

        // 加载对应guard的配置
        if (strpos(App::VERSION, '5.') !== 0) {
            $guardConfig = Config::get("jwt.guards.{$guard}");
        } else {
            $guardConfig = Config::get("jwt.guards.{$guard}.");
        }

        // 配置错误
        if (!$guardConfig) {
            throw new JWTException("Invalid configuration");
        }

        // 合并新的配置到当前配置
        $this->guard = $guard;
        $this->config = array_merge($this->config, $guardConfig);        
        return $this;
    }

    public function init()
    {
        $this->registerBlacklist();
        $this->registerProvider();
        $this->registerFactory();
        $this->registerPayload();
        $this->registerManager();
        $this->registerJWTAuth();
    }
}
