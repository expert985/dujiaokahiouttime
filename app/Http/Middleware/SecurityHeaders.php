<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * 安全响应头中间件
 *
 * 添加常见的安全响应头，增强应用安全性
 */
class SecurityHeaders
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        // 防止页面被嵌入iframe，防御点击劫持攻击
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');

        // 防止MIME类型嗅探
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // 启用XSS过滤器（旧版浏览器）
        $response->headers->set('X-XSS-Protection', '1; mode=block');

        // 强制HTTPS（仅在生产环境且使用HTTPS时）
        if (config('app.env') === 'production' && $request->secure()) {
            $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }

        // Referrer Policy - 控制Referer信息泄露
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');

        // Permissions Policy - 控制浏览器特性访问
        $response->headers->set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

        return $response;
    }
}
