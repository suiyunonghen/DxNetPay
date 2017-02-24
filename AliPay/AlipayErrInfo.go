//支付宝的SDK接口
//作者：不得闲
//错误与常量信息
package AliPay

import "fmt"
const(
	APC_Success 		= "10000"  //成功
	APC_ServiceDisabled	= "20000"  //服务不可用
	APC_NoTokenPermission	= "20001"  //授权权限不足
	APC_LostParams		= "40001"  //缺少必要的参数
	APC_InvalidaParams	= "40002"  //无效的参数
	APC_ServiceFailed	= "40004"  //处理业务失败
	APC_NoPermission	= "40006"  //权限不足
)

//淘宝支付的错误指定
type AlipayServiceError struct {
	ferrorCode      string   //错误代码
	fsuberrcode     string
	ferrMsg         string   //错误信息
	fsuberrMsg      string
}

func (err *AlipayServiceError)Error() string  {
	return fmt.Sprintf("错误代码：%s，错误消息：%s，详细代码：%s,详细错误信息：%s",err.ferrorCode,err.ferrMsg,
		err.fsuberrcode,err.fsuberrMsg)
}

func NewAlipayServiceErr(errcode, errmsg,suberrcode,subErrMsg string)error  {
	return &AlipayServiceError{errcode,suberrcode,errmsg,subErrMsg}
}

//获取支付宝的服务错误消息
func GetServiceErrMsg(errcode string)string  {
	switch errcode {
	case APC_ServiceDisabled:  	return "服务不可用"
	case APC_NoTokenPermission: 	return "授权权限不足"
	case APC_LostParams:		return "缺少必要的参数"
	case APC_InvalidaParams:	return "无效的参数"
	case APC_ServiceFailed:		return "处理业务失败"
	case APC_NoPermission:		return "权限不足"
	case "APP_NOT_ISV":		return "当前请求应用非第三方应用，请求失败"
	case "REFRESH_TOKEN_NOT_VALID": return "无效的刷新令牌"
	case "GRANT_TYPE_INVALID":	return "grant_type必须是authorization_code或者refresh_token"
	case "AUTH_CODE_NOT_EXIST":	return "auth_code不存在"
	case "APP_ID_NOT_CONSISTENT":	return "授权令牌授予的应用AppId与当前应用AppId不一致"
	case "AUTH_CODE_NOT_VALID":	return "无效的auth_code"
	case "AUTH_TOKEN_NOT_FOUND":	return "授权令牌不存在"
	case "REFRESH_TOKEN_NOT_EXIST": return "刷新令牌不存在"
	case "REFRESH_TOKEN_TIME_OUT":	return "刷新令牌过期"
	case "isp.unknow-error":	return "服务暂不可用（业务系统不可用）"
	case "aop.unknow-error":	return "服务暂不可用（网关自身的未知错误）"
	case "aop.invalid-auth-token":	return "无效的访问令牌"
	case "aop.auth-token-time-out":	return "访问令牌已过期"
	case "aop.invalid-app-auth-token": return "无效的应用授权令牌"
	case "aop.invalid-app-auth-token-no-api": return "商户未授权当前接口"
	case "aop.app-auth-token-time-out": return "应用授权令牌已过期"
	case "aop.no-product-reg-by-partner": return "商户未签约任何产品"
	case "isv.missing-method":	return "缺少方法名参数"
	case "isv.missing-signature":	return "缺少签名参数"
	case "isv.missing-signature-type": return "缺少签名类型参数"
	case "isv.missing-signature-key":	return "缺少签名配置"
	case "isv.missing-app-id":	return "缺少appId参数"
	case "isv.missing-timestamp":	return "检查请求参数，缺少timestamp参数"
	case "isv.missing-version":	return "缺少version参数"
	case "isv.decryption-error-missing-encrypt-type":  return "解密出错, 未指定加密算法,检查参数，缺少encrypt_type参数"
	case "isv.invalid-parameter":	return "参数无效"
	case "isv.upload-fail":		return "文件上传失败"
	case "isv.invalid-file-extension": return "文件扩展名无效"
	case "isv.invalid-file-size":	return "文件大小无效,目前支持最大为：50MB "
	case "isv.invalid-method":	return "检查入参method是否正确"
	case "isv.invalid-format":	return "检查入参format，目前只支持json和xml 2种格式"
	case "isv.invalid-signature-type": return "检查入参sign_type,目前只支持RSA,RSA2,HMAC_SHA1"
	case "isv.invalid-signature":	return "无效签名"
	case "isv.invalid-encrypt-type": return "无效的加密类型"
	case "isv.invalid-encrypt":	return "解密异常"
	case "isv.invalid-app-id":	return "无效的appId参数"
	case "isv.invalid-timestamp":	return `参数timestamp非法，请检查格式需要为"yyyy-MM-dd HH:mm:ss"`
	case "isv.invalid-charset":	return "请求参数charset错误，目前支持格式：GBK,UTF-8"
	case "isv.invalid-digest":	return "摘要错误"
	case "isv.decryption-error-not-valid-encrypt-type": return "检查入参encrypt_type，目前只支持AES"
	case "isv.decryption-error-not-valid-encrypt-key": return "解密出错, 未配置加密密钥或加密密钥格式错误"
	case "isv.decryption-error-unknown": return "解密出错，未知异常"
	case "isv.missing-signature-config": return "验签出错, 未配置对应签名算法的公钥或者证书"
	case "isv.not-support-app-auth": return "本接口不支持第三方代理调用"
	case "isv.insufficient-isv-permissions": return "ISV权限不足"
	case "isv.insufficient-user-permissions": return "用户权限不足"
	}
	return ""
}
