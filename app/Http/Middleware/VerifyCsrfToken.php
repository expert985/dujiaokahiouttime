<?php

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;

class VerifyCsrfToken extends Middleware
{
    /**
     * Indicates whether the XSRF-TOKEN cookie should be set on the response.
     *
     * @var bool
     */
    protected $addHttpCookie = true;

    /**
     * The URIs that should be excluded from CSRF verification.
     *
     * 安全修复: 仅豁免支付回调接口，支付网关入口需要CSRF保护
     *
     * @var array
     */
    protected $except = [
        'pay/*/notify',  // 支付异步回调通知（第三方POST）
        'pay/*/return',  // 支付同步返回（某些支付网关使用POST）
        'install',       // 安装接口
    ];
}
