package main

import (
	"suiyunonghen/DxNetPay/AliPay"
)


func main()  {
	PayClient := AliPay.NewAlipayCilient("AppID","PrivateKey")
	PayClient.Alipayurl = "https://openapi.alipay.com/gateway.do"
	PayClient.NotifyGateWayurl = "http://127.0.0.1:9909/AppGateWayNotify" //应用回调网关，必须是放到公网能访问的，并且是Post模式
	PayClient.SignType = AliPay.RSA2
	PayClient.TradeQuery(nil,"商户订单号","") //第一个参数Seller可以指定为卖家的信息，主要是需要包含卖家的授权令牌app_auth_token
	//PayClient.GetApp_Auth_Token(Seller)  //获得卖家的授权令牌，
	//PayClient.Query_Auth_Toker() 查询商户的授权
	//PayClient.TradeCreate()  创建订单,生成订单二维码
	//PayClient.TradeCancel()  订单撤销
	//PayClient.TradePay()  通过支付宝生成条码，来执行扫码支付
}
