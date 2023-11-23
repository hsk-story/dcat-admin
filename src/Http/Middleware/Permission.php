<?php

namespace Dcat\Admin\Http\Middleware;

use Dcat\Admin\Admin;
use Dcat\Admin\Exception\RuntimeException;
use Dcat\Admin\Http\Auth\Permission as Checker;
use Dcat\Admin\Models\Menu;
use Dcat\Admin\Support\Helper;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class Permission
{
    /**
     * @var string
     */
    protected $middlewarePrefix = 'admin.permission:';

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  array  $args
     * @return mixed
     */
    public function handle(Request $request, \Closure $next, ...$args)
    {
        $user = Admin::user();

        // ALTER TABLE `admin_menu` ADD COLUMN `bind_permission`  tinyint(1) NULL DEFAULT 0 COMMENT '自动关联uri权限' AFTER `show`;

        if (
            ! $user
            || ! empty($args)
            || ! config('admin.permission.enable')
            || $this->shouldPassThrough($request)
            || $user->isAdministrator()
            || $this->checkRoutePermission($request)
        ) {
            return $next($request);
        }

        $menuModel = config('admin.database.menu_model');
        $visibleNodes = (new $menuModel())->visibleNodesFromLogin();
        $uri = $request->decodedPath();
        foreach ($visibleNodes as $node) {
            if (empty($node['bind_permission'])) {
                continue;
            }
            if (empty($node['uri']) || $node['uri'] === '/') {
                continue;
            }
            if (Helper::matchRequestPath($node['uri'] . '*', $uri)) {
                return $next($request);
            }
        }


        if (! $user->allPermissions()->first(function ($permission) use ($request) {
            return $permission->shouldPassThrough($request);
        })) {
            Checker::error();
        }

        return $next($request);
    }

    /**
     * If the route of current request contains a middleware prefixed with 'admin.permission:',
     * then it has a manually set permission middleware, we need to handle it first.
     *
     * @param  Request  $request
     * @return bool
     */
    public function checkRoutePermission(Request $request)
    {
        if (! $middleware = collect($request->route()->middleware())->first(function ($middleware) {
            return Str::startsWith($middleware, $this->middlewarePrefix);
        })) {
            return false;
        }

        $args = explode(',', str_replace($this->middlewarePrefix, '', $middleware));

        $method = array_shift($args);

        if (! method_exists(Checker::class, $method)) {
            throw new RuntimeException("Invalid permission method [$method].");
        }

        call_user_func_array([Checker::class, $method], [$args]);

        return true;
    }

    /**
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function isApiRoute($request)
    {
        return $request->routeIs(admin_api_route_name('*'));
    }

    /**
     * Determine if the request has a URI that should pass through verification.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    public function shouldPassThrough($request)
    {
        if ($this->isApiRoute($request) || Authenticate::shouldPassThrough($request)) {
            return true;
        }

        $excepts = array_merge(
            (array) config('admin.permission.except', []),
            Admin::context()->getArray('permission.except')
        );

        foreach ($excepts as $except) {
            if ($request->routeIs($except) || $request->routeIs(admin_route_name($except))) {
                return true;
            }

            $except = admin_base_path($except);

            if ($except !== '/') {
                $except = trim($except, '/');
            }

            if (Helper::matchRequestPath($except)) {
                return true;
            }
        }

        return false;
    }
}
