<?php

namespace Dcat\Admin\Models;

use Dcat\Admin\Admin;
use Dcat\Admin\Support\Helper;
use Dcat\Admin\Traits\HasDateTimeFormatter;
use Dcat\Admin\Traits\ModelTree;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Spatie\EloquentSortable\Sortable;

/**
 * Class Menu.
 *
 * @property int $id
 *
 * @method where($parent_id, $id)
 */
class Menu extends Model implements Sortable
{
    use HasDateTimeFormatter,
        MenuCache,
        ModelTree {
            allNodes as treeAllNodes;
            ModelTree::boot as treeBoot;
        }

    /**
     * @var array
     */
    protected $sortable = [
        'sort_when_creating' => true,
    ];

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = ['parent_id', 'order', 'title', 'icon', 'uri', 'extension', 'show'];

    /**
     * Create a new Eloquent model instance.
     *
     * @param  array  $attributes
     */
    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);

        $this->init();
    }

    protected function init()
    {
        $connection = config('admin.database.connection') ?: config('database.default');

        $this->setConnection($connection);

        $this->setTable(config('admin.database.menu_table'));
    }

    /**
     * A Menu belongs to many roles.
     *
     * @return BelongsToMany
     */
    public function roles(): BelongsToMany
    {
        $pivotTable = config('admin.database.role_menu_table');

        $relatedModel = config('admin.database.roles_model');

        return $this->belongsToMany($relatedModel, $pivotTable, 'menu_id', 'role_id')->withTimestamps();
    }

    public function permissions(): BelongsToMany
    {
        $pivotTable = config('admin.database.permission_menu_table');

        $relatedModel = config('admin.database.permissions_model');

        return $this->belongsToMany($relatedModel, $pivotTable, 'menu_id', 'permission_id')->withTimestamps();
    }

    /**
     * Get all elements.
     *
     * @param  bool  $force
     * @return static[]|\Illuminate\Support\Collection
     */
    public function allNodes(bool $force = false)
    {
        if ($force || $this->queryCallbacks) {
            return $this->fetchAll();
        }

        return $this->remember(function () {
            return $this->fetchAll();
        });
    }

    public function visibleNodesFromLogin($force = false)
    {
        if(session()->has('_menu') && !$force) {
            return session()->get('_menu');
        }
        $nodes = $this->allNodes(true)->filter(function ($item) {
            return $this->visible($item);
        })->values()->toArray();
        session()->put('_menu', $nodes);
        return $nodes;
    }

    /**
     * Fetch all elements.
     *
     * @return static[]|\Illuminate\Support\Collection
     */
    public function fetchAll()
    {
        return $this->withQuery(function ($query) {
            if (static::withPermission()) {
                $query = $query->with('permissions');
            }

            return $query->with('roles');
        })->treeAllNodes();
    }

    /**
     * Determine if enable menu bind permission.
     *
     * @return bool
     */
    public static function withPermission()
    {
        return config('admin.menu.bind_permission') && config('admin.permission.enable');
    }

    /**
     * Determine if enable menu bind role.
     *
     * @return bool
     */
    public static function withRole()
    {
        return (bool) config('admin.permission.enable');
    }

    /**
     * Detach models from the relationship.
     *
     * @return void
     */
    protected static function boot()
    {
        static::treeBoot();

        static::deleting(function ($model) {
            $model->roles()->detach();
            $model->permissions()->detach();

            $model->flushCache();
        });

        static::saved(function ($model) {
            $model->flushCache();
        });
    }

    /**
     * 判断节点是否可见.
     *
     * @param  array  $item
     * @return bool
     */
    public function visible($item)
    {
        if (
            ! $this->checkPermission($item)
            || ! $this->checkExtension($item)
            || ! $this->userCanSeeMenu($item)
        ) {
            return false;
        }

        $show = $item['show'] ?? null;
        if ($show !== null && ! $show) {
            return false;
        }

        return true;
    }

    /**
     * 判断扩展是否启用.
     *
     * @param $item
     * @return bool
     */
    protected function checkExtension($item)
    {
        $extension = $item['extension'] ?? null;

        if (! $extension) {
            return true;
        }

        if (! $extension = Admin::extension($extension)) {
            return false;
        }

        return $extension->enabled();
    }

    /**
     * 判断用户.
     *
     * @param  array|\Dcat\Admin\Models\Menu  $item
     * @return bool
     */
    protected function userCanSeeMenu($item)
    {
        $user = Admin::user();

        if (! $user || ! method_exists($user, 'canSeeMenu')) {
            return true;
        }

        return $user->canSeeMenu($item);
    }

    /**
     * 判断权限.
     *
     * @param $item
     * @return bool
     */
    protected function checkPermission($item)
    {
        $permissionIds = $item['permission_id'] ?? null;
        $roles = array_column(Helper::array($item['roles'] ?? []), 'slug');
        $permissions = array_column(Helper::array($item['permissions'] ?? []), 'slug');

        $user = Admin::user();

        if (! $user || $user->isAdministrator() || $user->visible($roles)) {
            return true;
        }

        if (! $permissionIds && ! $roles && ! $permissions) {
            return false;
        }

        foreach (array_merge(Helper::array($permissionIds), $permissions) as $permission) {
            if ($user->can($permission)) {
                return true;
            }
        }

        return false;
    }
}
