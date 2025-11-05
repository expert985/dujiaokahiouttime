<?php

namespace App\Services;

use App\Exceptions\RuleValidationException;
use App\Models\Goods;
use App\Models\Coupon;
use App\Models\Order;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator as LaravelValidator;

/**
 * 统一验证服务
 */
class Validator
{
    protected Shop $goodsService;
    protected Coupons $couponService;

    public function __construct()
    {
        $this->goodsService = app('App\Services\Shop');
        $this->couponService = app('App\Services\Coupons');
    }

    /**
     * 验证商品状态
     */
    public function validateGoodsStatus(Goods $goods): Goods
    {
        if (empty($goods)) {
            throw new RuleValidationException(__('dujiaoka.prompt.goods_does_not_exist'));
        }
        
        if ($goods->is_open != Goods::STATUS_OPEN) {
            throw new RuleValidationException(__('dujiaoka.prompt.the_goods_is_not_on_the_shelves'));
        }
        
        return $goods;
    }

    /**
     * 验证商品库存
     */
    public function validateGoodsStock(Goods $goods, int $quantity = 1): void
    {
        if ($goods->type == Goods::AUTOMATIC_DELIVERY && $goods->stock < $quantity) {
            throw new RuleValidationException(__('dujiaoka.prompt.insufficient_inventory'));
        }
    }

    /**
     * 验证优惠券
     */
    public function validateCoupon(Request $request): ?Coupon
    {
        if ($request->filled('coupon_code')) {
            $coupon = $this->couponService->withHasGoods($request->input('coupon_code'), $request->input('gid'));
            
            if (!$coupon) {
                throw new RuleValidationException(__('dujiaoka.prompt.coupon_does_not_exist'));
            }
            
            if ($coupon->is_open != Coupon::STATUS_OPEN) {
                throw new RuleValidationException(__('dujiaoka.prompt.coupon_disabled'));
            }
            
            return $coupon;
        }
        
        return null;
    }

    /**
     * 验证订单创建请求
     *
     * 安全修复: 增加订单查询密码的强度要求
     */
    public function validateOrderRequest(Request $request): void
    {
        $validator = LaravelValidator::make($request->all(), [
            'gid' => 'required|integer',
            'email' => ['required', 'email'],
            'payway' => ['required', 'integer'],
            'search_pwd' => ['nullable', 'string', 'min:8', 'max:255'],
        ], [
            'search_pwd.min' => '查询密码至少需要8个字符，以保护您的订单安全',
        ]);

        if ($validator->fails()) {
            throw new RuleValidationException($validator->errors()->first());
        }

        // 额外验证: 检查查询密码不能是纯数字或过于简单
        if ($request->filled('search_pwd')) {
            $searchPwd = $request->input('search_pwd');

            // 检查是否为纯数字
            if (ctype_digit($searchPwd)) {
                throw new RuleValidationException('查询密码不能是纯数字，请使用字母和数字的组合');
            }

            // 检查是否为常见弱密码
            $weakPasswords = ['12345678', '00000000', '11111111', 'password', 'abcd1234', '87654321'];
            if (in_array(strtolower($searchPwd), $weakPasswords)) {
                throw new RuleValidationException('此密码过于简单，请使用更复杂的密码保护您的订单');
            }
        }
    }

    /**
     * 验证商品限购
     */
    public function validatePurchaseLimit(Goods $goods, string $email, int $quantity): void
    {
        if ($goods->buy_limit_num > 0) {
            $count = Order::where('goods_id', $goods->id)
                ->where('email', $email)
                ->whereIn('status', [Order::STATUS_COMPLETED, Order::STATUS_PROCESSING, Order::STATUS_PENDING])
                ->sum('buy_amount');
                
            if (($count + $quantity) > $goods->buy_limit_num) {
                throw new RuleValidationException(__('dujiaoka.prompt.purchase_limit_exceeded'));
            }
        }
    }
}