<?php

namespace App\Models;

use Filament\Models\Contracts\FilamentUser;
use Filament\Panel;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Spatie\Permission\Traits\HasRoles;

class AdminUser extends Authenticatable implements FilamentUser
{
    use HasFactory, Notifiable, HasRoles;

    protected $table = 'admin_users';
    
    /**
     * 设置权限系统的guard
     */
    protected $guard_name = 'admin';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'username',
        'password',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'password' => 'hashed',
        ];
    }

    /**
     * Determine if the user can access the Filament admin panel.
     *
     * 安全修复: 添加基于角色的访问控制
     * 仅允许具有管理员角色的激活用户访问
     */
    public function canAccessPanel(Panel $panel): bool
    {
        // 检查用户是否有管理员相关角色
        return $this->hasAnyRole(['super-admin', 'admin', 'manager', 'order-processor']);
    }

}