//支付宝的SDK接口
//作者：不得闲
package AliPay

import (
	"github.com/valyala/fasthttp"
	"time"
	"fmt"
	"sort"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha1"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"sync"
	"hash"
)

type SignType byte
type ResponseStatus byte
//签名样式sign_type
const(
	RSA SignType=iota
	RSA2
)

const(
	RS_Error ResponseStatus=iota //执行失败
	RS_Valid	//返回有效
	RS_Invalid     //返回无效状态
	RS_Request_Retry  //请求需要重试
)
type AliPayClient struct {
	fAppId	string
	fPrivateKey string    //用户私钥
	SignType   SignType  //签名算法类型
	Alipayurl string      //阿里巴巴的API网关
	NotifyGateWayurl  string	//应用网关，回调通知
	ClientUid	  string 	//主要用来设置支付中的系统商的PID,sys_service_provider_id
}

//订单操作的返回结构
type TradeResponse struct {
	Status 		ResponseStatus //返回状态
	Action		string 		//动作
	Trade_no	string		//支付宝交易号
	Out_trade_no	string 		//商户订单号
}
//淘宝账户信息
type TaoBoUserInfo struct {
	UserID		string   //支付宝账户ID
	Name 	        string   //账户名称
	Auth_code       string   //授权码
	Auth_token      string   //授权令牌
	Refresh_token   string   //刷新令牌
	Expires_in      uint      //令牌有效时间长度
	Re_Expires_in   uint      //刷新令牌有效时间长度
	Sign            string   //返回的签名
}

//商品信息
type GoodInfo struct {
	Goods_id		string	`json:"goods_id"`
	Alipay_goods_id		string	`json:"alipay_goods_id"`
	Goods_name		string	`json:"goods_name"`
	Quantity		float32	`json:"quantity"`
	Price			float32	`json:"price"`
	Goods_category		string	`json:"goods_category"`
	Body			string	`json:"body"`
	Show_url		string	`json:"show_url"`
}

func (good *GoodInfo)JsonString()string  {
	result := fmt.Sprintf(`{"goods_id":"%s"`,good.Goods_id)
	if good.Alipay_goods_id != ""{
		result = fmt.Sprintf(`%s,"alipay_goods_id":"%s"`,result,good.Alipay_goods_id)
	}
	result = fmt.Sprintf(`%s,"goods_name":"%s","quantity":%.2f,"price":%.2f`, result,good.Goods_name,good.Quantity,good.Price)
	if good.Goods_category != ""{
		result = fmt.Sprintf(`%s,"goods_category":"%s"`,result,good.Goods_category)
	}
	if good.Body != ""{
		result = fmt.Sprintf(`%s,"body":"%s"`,result,good.Body)
	}
	if good.Show_url != ""{
		result = fmt.Sprintf(`%s,"show_url":"%s"`,result,good.Show_url)
	}
	result = fmt.Sprintf(`%s}`,result)
	return result
}

//订单信息
type TradeInfo struct {
	Trade_No	string   	`json:"out_trade_no"`//商户订单号,64个字符以内
	Seller_Uid	string 	 	`json:"seller_id"`//商户的账户ID
	Total_amount	float64  	`json:"total_amount"`//订单总金额，单位为元
	Discountable_amount  float64  	`json:"discountable_amount"`//可打折金额. 参与优惠计算的金额
	Undiscountable_amount float64 	`json:"undiscountable_amount"`//不可打折金额
	Buyer_logon_id	string   	`json:"buyer_logon_id"`//买家支付宝账户ID
	Subject		string 		`json:"subject"`//订单标题
	Body		string   	`json:"body"`//订单描述
	Operator_id	string 	 	`json:"operator_id"`//商户操作员编号
	Store_id	string 	 	`json:"store_id"`//商户门店编号
	Terminal_id	string 	 	`json:"terminal_id"`//商户机具终端编号
	Alipay_store_id string	 	`json:"alipay_store_id"`//支付宝店铺的门店ID
	Goods_detail	[]*GoodInfo  	`json:"goods_detail"`//商品明细
	Auth_code	string		`json:"auth_code"`	//用户的付款码（条形或者二维码）
	Scene		string		`json:"scene"`    //支付场景 条码支付，取值：bar_code 声波支付，取值：wave_code
}


//根据订单信息生成支付参数biz_content
func (tradeinfo *TradeInfo)biz_content(sys_service_provider_id string)string  {
	result := fmt.Sprintf(`{"out_trade_no":"%s"`,tradeinfo.Trade_No)
	if tradeinfo.Seller_Uid != ""{
		result = fmt.Sprintf(`%s,"seller_id":"%s"`,result,tradeinfo.Seller_Uid)
	}
	//扫描枪扫手机支付码的时候，会有这个scene和auth_code两个参数
	if tradeinfo.Scene != ""{
		result = fmt.Sprintf(`%s,"scene":"%s"`,result,tradeinfo.Scene)
	}
	if tradeinfo.Auth_code != ""{
		result = fmt.Sprintf(`%s,"auth_code":"%s"`,result,tradeinfo.Auth_code)
	}

	result = fmt.Sprintf(`%s,"total_amount":%.2f`,result,tradeinfo.Total_amount)
	if tradeinfo.Discountable_amount !=0 {
		result = fmt.Sprintf(`%s,"discountable_amount":%.2f`,result,tradeinfo.Discountable_amount)
	}
	if tradeinfo.Undiscountable_amount !=0 {
		result = fmt.Sprintf(`%s,"undiscountable_amount":%.2f`,result,tradeinfo.Undiscountable_amount)
	}
	if tradeinfo.Buyer_logon_id != ""{
		result = fmt.Sprintf(`%s,"buyer_logon_id":"%s"`,result,tradeinfo.Buyer_logon_id)
	}
	if tradeinfo.Subject != ""{
		result = fmt.Sprintf(`%s,"subject":"%s"`,result,tradeinfo.Subject)
	}
	if tradeinfo.Body != ""{
		result = fmt.Sprintf(`%s,"body":"%s"`,result,tradeinfo.Body)
	}
	if tradeinfo.Operator_id !=""{
		result = fmt.Sprintf(`%s,"operator_id":"%s"`,result,tradeinfo.Operator_id)
	}
	if tradeinfo.Store_id != ""{
		result = fmt.Sprintf(`%s,"store_id":"%s"`,result,tradeinfo.Store_id)
	}
	if tradeinfo.Terminal_id !=""{
		result = fmt.Sprintf(`%s,"terminal_id":"%s"`,result,tradeinfo.Terminal_id)
	}
	if tradeinfo.Alipay_store_id !=""{
		result = fmt.Sprintf(`%s,"alipay_store_id":"%s"`,result,tradeinfo.Alipay_store_id)
	}
	if sys_service_provider_id !=""{
		exprams := fmt.Sprintf(`{"sys_service_provider_id":"%s"}`,sys_service_provider_id)
		result = fmt.Sprintf(`%s,"extend_params":"%s"`,result,exprams)
	}
	result = fmt.Sprintf(`%s,"timeout_express":"90m"`,result)
	if tradeinfo.Goods_detail !=nil && len(tradeinfo.Goods_detail)!=0{
		goodsDetail := ""
		for _,v := range tradeinfo.Goods_detail {
			if goodsDetail == ""{
				goodsDetail = v.JsonString()
			}else{
				goodsDetail = fmt.Sprintf("%s,%s",goodsDetail,v.JsonString())
			}
		}
		result = fmt.Sprintf(`%s,"goods_detail":[%s]`,result,goodsDetail)
	}
	result = fmt.Sprintf(`%s}`,result)
	return result
}

type argValue struct {
	Name     string
	Value    string
}

var (
	InvalidResponseErr = errors.New("无效的命令返回信息")
	InvalidPrivateKeyErr = errors.New("无效的私钥")
	ParsePrivateKeyErr = errors.New("ParsePKCS1PrivateKey失效")
	SignPKCS1v15Err = errors.New("SignPKCS1v15执行失败")
)


//支付方法
type AlipayMethod struct {
	Name			string 		//SDK方法
	httpclient	  	fasthttp.Client
	args			[16]argValue    //参数
	sign_type		string
	ver			string
	fargIndex		int
	fAppId			string
}

//填充基础参数
func (method *AlipayMethod)FillNormalargs()  {
	method.args[0].Name = "app_id"
	method.args[0].Value = method.fAppId
	method.args[1].Name = "method"
	method.args[1].Value = method.Name
	method.args[2].Name = "format"
	method.args[2].Value = "JSON"
	method.args[3].Name = "sign_type"
	method.args[3].Value = method.sign_type
	method.args[4].Name = "timestamp"
	method.args[4].Value = time.Now().Format("2006-01-02 15:04:05")
	method.args[5].Name = "version"
	if method.ver == ""{
		method.args[5].Value = "1.0"
	}else{
		method.args[5].Value = method.ver
	}

	method.args[6].Name = "charset"
	method.args[6].Value = "utf-8"
	method.fargIndex = 7
}

func (method *AlipayMethod)appendArg(argName,argvalue string)  {
	method.args[method.fargIndex].Name = argName
	method.args[method.fargIndex].Value = argvalue
	method.fargIndex++
}

func (method *AlipayMethod)ReSet()  {
	method.Name = ""
	method.fAppId = ""
	method.fargIndex = 0
	method.ver = ""
}

func (method *AlipayMethod)Call(client *AliPayClient)([]byte, error)  {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer func(){
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()
	//执行命令提交
	req.SetRequestURI(client.Alipayurl) //API网关
	err := client.getSign(method.args[:method.fargIndex],req)
	if err != nil{
		return nil,err
	}
	err = method.httpclient.Do(req,resp)
	if err != nil{
		return nil,err
	}
	return resp.Body(),nil
}

var(
	methodPool	sync.Pool  //方法池
)

func getMethod(methodName,appid,sign_type string)*AlipayMethod  {
	v := methodPool.Get()
	var m *AlipayMethod
	if v == nil {
		m = new(AlipayMethod)
	}else{
		m = v.(*AlipayMethod)
	}
	m.Name = methodName
	m.fAppId = appid
	m.sign_type = sign_type
	m.httpclient.Name = "DxHttpClient"
	return m
}

func freeMethod(method *AlipayMethod)  {
	method.ReSet()
	methodPool.Put(method)
}
//根据参数获得签名
func (client *AliPayClient)getSign(args []argValue,req *fasthttp.Request) error {
	sort.Slice(args,func(i, j int) bool{
		return args[i].Name < args[j].Name
	})
	result := ""
	reqargs := req.URI().QueryArgs()
	for i:=0;i<len(args);i++{
		reqargs.Add(args[i].Name,args[i].Value)
		if i == 0{
			result = fmt.Sprintf("%s=%s",args[i].Name,args[i].Value)
		}else{
			result = fmt.Sprintf("%s&%s=%s",result,args[i].Name,args[i].Value)
		}
	}
	//通过RSA签名
	block, _ := pem.Decode(([]byte)(client.fPrivateKey))
	if block == nil{
		return InvalidPrivateKeyErr
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil{
		return  ParsePrivateKeyErr
	}
	result,err = client.RsaSign(result,privateKey) //签名
	if err != nil{
		return err
	}
	reqargs.Add("sign",result)
	return nil
}

//RSA签名
func (client *AliPayClient)RsaSign(origData string, privateKey *rsa.PrivateKey) (string, error) {
	var (
		h hash.Hash
		hashtype crypto.Hash
	)
	if client.SignType == RSA2{
		h = sha256.New()
		hashtype = crypto.SHA256
	}else{
		h = sha1.New()
		hashtype = crypto.SHA1
	}
	h.Write([]byte(origData))
	digest := h.Sum(nil)
	s, err := rsa.SignPKCS1v15(nil, privateKey, hashtype, digest)
	if err != nil {
		return "", SignPKCS1v15Err
	}
	data := base64.StdEncoding.EncodeToString(s)
	return string(data), nil
}

func (client *AliPayClient)getSignType()string  {
	if client.SignType == RSA{
		return "RSA"
	}
	return "RSA2"
}

//查询某个应用授权AppAuthToken的授权信息
func (client *AliPayClient)Query_Auth_Toker(userinfo *TaoBoUserInfo)(ResponseStatus,error){
	method := getMethod("alipay.open.auth.token.app.query",client.fAppId,client.getSignType())
	defer freeMethod(method)
	method.FillNormalargs()
	method.appendArg("biz_content",fmt.Sprintf(`{"app_auth_token":"%s"}`,userinfo.Auth_token))
	body,err := method.Call(client)
	if err == InvalidResponseErr || err == InvalidPrivateKeyErr ||
	   err == ParsePrivateKeyErr || err == SignPKCS1v15Err{
		return RS_Error,err
	}
	ok := false
	var v interface{}
	result := make(map[string]interface{})
	err = json.Unmarshal(body,&result)
	if err != nil{
		return RS_Error,err
	}
	if v,ok = result["alipay_open_auth_token_app_query_response"];!ok{
		return RS_Error,InvalidResponseErr
	}
	responsemap := v.(map[string]interface{})
	code := responsemap["code"].(string)
	if code == APC_Success {//执行成功
		if responsemap["status"].(string)=="valid"{
			return RS_Valid,nil
		}else{
			return RS_Invalid,nil
		}
	}else{
		return RS_Error,parserResponseErr(responsemap)
	}
}

func parserResponseErr(responsemap map[string]interface{}) error {
	errmsg := responsemap["msg"].(string)
	var (
		vtemp interface{}
		subcode,submsg string
		ok bool
	)
	if vtemp,ok = responsemap["sub_code"];ok{
		subcode = vtemp.(string)
	}else{
		subcode = ""
	}

	if vtemp,ok = responsemap["sub_msg"];ok{
		submsg = vtemp.(string)
	}else{
		submsg = ""
	}
	return NewAlipayServiceErr(responsemap["code"].(string),errmsg,subcode,submsg)
}

//获取淘宝账户的授权令牌
func (client *AliPayClient)GetApp_Auth_Token(userinfo *TaoBoUserInfo)([]byte,error)  {
	method := getMethod("alipay.open.auth.token.app",client.fAppId,client.getSignType())
	defer freeMethod(method)
	method.FillNormalargs()
	method.appendArg("biz_content",fmt.Sprintf(`{"grant_type":"authorization_code","code":"%s"}`,userinfo.Auth_code))
	body,err := method.Call(client)
	if err == nil{
		//执行成功，返回数据
		ok := false
		var v interface{}
		result := make(map[string]interface{})
		err = json.Unmarshal(body,&result)
		if err != nil{
			return nil,err
		}
		if v,ok = result["alipay_open_auth_token_app_response"];!ok{
			return nil,InvalidResponseErr
		}else{
			responsemap := v.(map[string]interface{})
			code := responsemap["code"].(string)
			if code == APC_Success{//执行成功
				userinfo.Auth_token = responsemap["app_auth_token"].(string)
				userinfo.Refresh_token = responsemap["app_refresh_token"].(string)
				vin := responsemap["expires_in"]
				switch vin.(type) {
				case uint:
					userinfo.Expires_in = vin.(uint)
					userinfo.Re_Expires_in = responsemap["re_expires_in"].(uint)
				case int:
					userinfo.Expires_in = uint(vin.(int))
					userinfo.Re_Expires_in = uint(responsemap["re_expires_in"].(int))
				case uint32:
					userinfo.Expires_in = uint(vin.(uint32))
					userinfo.Re_Expires_in = uint(responsemap["re_expires_in"].(uint32))
				case int32:
					userinfo.Expires_in = uint(vin.(int32))
					userinfo.Re_Expires_in = uint(responsemap["re_expires_in"].(int32))
				case int64:
					userinfo.Expires_in = uint(vin.(int64))
					userinfo.Re_Expires_in = uint(responsemap["re_expires_in"].(int64))
				case uint64:
					userinfo.Expires_in = uint(vin.(uint64))
					userinfo.Re_Expires_in = uint(responsemap["re_expires_in"].(uint64))
				case float32:
					userinfo.Expires_in = uint(vin.(float32))
					userinfo.Re_Expires_in = uint(responsemap["re_expires_in"].(float32))
				case float64:
					userinfo.Expires_in = uint(vin.(float64))
					userinfo.Re_Expires_in = uint(responsemap["re_expires_in"].(float64))
				}
				userinfo.UserID = responsemap["user_id"].(string)
				userinfo.Sign = result["sign"].(string)
			}else{//执行失败了
				return nil,parserResponseErr(responsemap)
			}
		}
		return body,nil
	}
	return nil,err
}

//扫码支付，下订单功能函数，生成二维码
//seller商家的支付宝账户信息,如果Seller为nil，则表示商户就是自己
//IsPreviewCreate指定是否是预下单，线下扫码，设置为True
func (client *AliPayClient)TradeCreate(seller *TaoBoUserInfo,trade *TradeInfo,IsPreviewCreate bool)(string,error)  {
	trade.Auth_code = ""
	trade.Scene = ""
	method := getMethod("alipay.trade.precreate",client.fAppId,client.getSignType())
	if !IsPreviewCreate{
		method.Name = "alipay.trade.create"//非预下单
	}
	if seller!=nil{
		trade.Seller_Uid = seller.UserID //指定为商户ID
	}else{
		trade.Seller_Uid = ""
	}
	defer freeMethod(method)
	method.FillNormalargs()
	if seller!=nil{
		method.appendArg("app_auth_token",seller.Auth_token) //指定授权令牌
	}
	//指定回调应用网关
	if client.NotifyGateWayurl != ""{
		method.appendArg("notify_url",client.NotifyGateWayurl)
	}

 	method.appendArg("biz_content",trade.biz_content(client.ClientUid))
	body,err := method.Call(client)
	if err !=nil{
		return "",err
	}
	//执行成功，会返回一个二维码
	var(
		v interface{}
		ok bool
	)
	result := make(map[string]interface{})
	err = json.Unmarshal(body,&result)
	if v,ok = result["alipay_trade_precreate_response"];!ok{
		return "",InvalidResponseErr
	}
	responsemap := v.(map[string]interface{})
	code := responsemap["code"].(string)
	if code == APC_Success {//执行成功
		return responsemap["qr_code"].(string),nil
	}else{
		return "",parserResponseErr(responsemap)
	}
}

//撤销预下订单功能
//一般是支付情况未知，或者超时等情况下，使用本功能，其他情况使用退款
//out_trade_no，原商户订单的订单号
//trade_no，支付宝产生的支付订单号
func (client *AliPayClient)TradeCancel(seller *TaoBoUserInfo,out_trade_no,trade_no string)(*TradeResponse,error)  {
	if out_trade_no == "" && trade_no == ""{
		return nil,errors.New("out_trade_no和trade_no不能同时为空")
	}
	method := getMethod("alipay.trade.cancel",client.fAppId,client.getSignType())
	defer freeMethod(method)
	method.FillNormalargs()
	if seller!=nil{
		method.appendArg("app_auth_token",seller.Auth_token) //指定授权令牌
	}
	method.appendArg("biz_content",func()string{
		result := "{"
		if out_trade_no != ""{
			result = fmt.Sprintf(`%s"out_trade_no":"%s"`,result,out_trade_no)
		}
		if trade_no != ""{
			if result == "{"{
				result = fmt.Sprintf(`%s,"trade_no":"%s"}`,result,trade_no)
			}else{
				result = fmt.Sprintf(`%s"trade_no":"%s"}`,result,trade_no)
			}
		}else{
			result=fmt.Sprintf("%s}",result)
		}
		return result
	}())
	body,err := method.Call(client)
	if err == InvalidResponseErr || err == InvalidPrivateKeyErr ||
		err == ParsePrivateKeyErr || err == SignPKCS1v15Err{
		return nil,err
	}
	var(
		v interface{}
		ok bool
	)
	result := make(map[string]interface{})
	err = json.Unmarshal(body,&result)
	if v,ok = result["alipay_trade_cancel_response"];!ok{
		return nil,InvalidResponseErr
	}
	responsemap := v.(map[string]interface{})
	code := responsemap["code"].(string)
	if code == APC_Success{ //执行返回成功
		tradeRes := new(TradeResponse)
		if v,ok = responsemap["action"];ok{
			tradeRes.Action = v.(string)
		}
		if v,ok = responsemap["out_trade_no"];ok{
			tradeRes.Out_trade_no = v.(string)
		}
		if v,ok = responsemap["trade_no"];ok{
			tradeRes.Trade_no = v.(string)
		}
		if responsemap["retry_flag"].(string)=="N"{
			tradeRes.Status = RS_Valid
		}else{
			tradeRes.Status = RS_Request_Retry
		}
		return tradeRes,nil
	}else{
		return nil,parserResponseErr(responsemap)
	}
}


//统一收单线下交易查询alipay.trade.query
func (client *AliPayClient)TradeQuery(seller *TaoBoUserInfo,out_trade_no,trade_no string)(map[string]interface{},error)  {
	if out_trade_no == "" && trade_no == ""{
		return nil,errors.New("out_trade_no和trade_no不能同时为空")
	}
	method := getMethod("alipay.trade.query",client.fAppId,client.getSignType())
	defer freeMethod(method)
	method.FillNormalargs()
	if seller!=nil{
		method.appendArg("app_auth_token",seller.Auth_token) //指定授权令牌
	}
	method.appendArg("biz_content",func()string{
		result := "{"
		if out_trade_no != ""{
			result = fmt.Sprintf(`%s"out_trade_no":"%s"`,result,out_trade_no)
		}
		if trade_no != ""{
			if result == "{"{
				result = fmt.Sprintf(`%s,"trade_no":"%s"}`,result,trade_no)
			}else{
				result = fmt.Sprintf(`%s"trade_no":"%s"}`,result,trade_no)
			}
		}else{
			result=fmt.Sprintf("%s}",result)
		}
		return result
	}())
	body,err := method.Call(client)
	if err == InvalidResponseErr || err == InvalidPrivateKeyErr ||
		err == ParsePrivateKeyErr || err == SignPKCS1v15Err{
		return nil,err
	}
	result := make(map[string]interface{})
	err = json.Unmarshal(body,&result)
	var(
		v interface{}
		ok bool
	)
	if v,ok = result["alipay_trade_query_response"];!ok{
		return nil,InvalidResponseErr
	}
	responsemap := v.(map[string]interface{})
	code := responsemap["code"].(string)
	if code == APC_Success {
		//执行返回成功
		return responsemap,nil
	}else{
		return nil,parserResponseErr(responsemap)
	}
}


//alipay.trade.pay
//统一收单交易支付接口，条码支付
func (client *AliPayClient)TradePay(seller *TaoBoUserInfo,trade *TradeInfo)(map[string]interface{},error)  {
	if trade.Auth_code=="" || trade.Scene==""{
		return nil,errors.New("必须指定付款码和付款方式")
	}
	if trade.Scene != "bar_code" && trade.Scene != "wave_code"{
		return nil,errors.New("Scene必须指定为bar_code或者wave_code")
	}
	method := getMethod("alipay.trade.pay",client.fAppId,client.getSignType())
	if seller!=nil{
		trade.Seller_Uid = seller.UserID //指定为商户ID
	}else{
		trade.Seller_Uid = ""
	}
	defer freeMethod(method)
	method.FillNormalargs()
	if seller!=nil{
		method.appendArg("app_auth_token",seller.Auth_token) //指定授权令牌
	}
	//指定回调应用网关
	if client.NotifyGateWayurl != ""{
		method.appendArg("notify_url",client.NotifyGateWayurl)
	}
	method.appendArg("biz_content",trade.biz_content(client.ClientUid))
	body,err := method.Call(client)
	if err !=nil{
		return nil,err
	}
	var(
		v interface{}
		ok bool
	)
	result := make(map[string]interface{})
	err = json.Unmarshal(body,&result)
	if v,ok = result["alipay_trade_precreate_response"];!ok{
		return nil,InvalidResponseErr
	}
	responsemap := v.(map[string]interface{})
	code := responsemap["code"].(string)
	if code == APC_Success {//执行成功
		return responsemap,nil
	}else{
		return nil,parserResponseErr(responsemap)
	}
}

func NewAlipayCilient(appId string,privatekey string)*AliPayClient  {
	result := new(AliPayClient)
	result.SignType = RSA2 //默认采用RSA2算法
	result.fAppId = appId
	result.fPrivateKey = privatekey
	return result
}
