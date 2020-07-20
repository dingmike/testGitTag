# 微信公众号消息加解密(node实现)

## 1.抽出一个加密模块 `WXMsgCrypto.js`:

```javascript
var crypto = require('crypto')

class PKCS7 {
  /**
   * 删除补位
   * @param {String} text 解密后的明文
   */
  decode(text) {
    let pad = text[text.length - 1]
    if (pad < 1 || pad > 32) {
      pad = 0
    }
    return text.slice(0, text.length - pad)
  }
  /**
   * 填充补位
   * @param {String} text 需要进行填充补位的明文
   */
  encode(text) {
    const blockSize = 32
    const textLength = text.length
    // 计算需要填充的位数
    const amountToPad = blockSize - (textLength % blockSize)
    const result = Buffer.alloc(amountToPad)
    result.fill(amountToPad)
    return Buffer.concat([text, result])
  }
}

/**
 * 微信公众号消息加解密
 * 官方文档(写的非常之烂)：https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Message_Encryption/Technical_Plan.html
 */
class WXMsgCrypto {
  /**
   * 以下信息在公众号 - 开发 - 基本配置
   * @param {String} token          令牌(Token)
   * @param {String} encodingAESKey 消息加解密密钥
   * @param {String} appId          公众号的AppId
   */
  constructor(token, encodingAESKey, appId) {
    if (!token || !encodingAESKey || !appId) {
      throw new Error('please check arguments')
    }
    this.token = token
    this.appId = appId

    let AESKey = Buffer.from(encodingAESKey + '=', 'base64')
    if (AESKey.length !== 32) {
      throw new Error('encodingAESKey invalid')
    }
    this.key = AESKey
    this.iv = AESKey.slice(0, 16)
    this.pkcs7 = new PKCS7()
  }
  /**
   * 获取签名
   * @param {String} timestamp    时间戳
   * @param {String} nonce        随机数
   * @param {String} encrypt      加密后的文本
   */
  getSignature(timestamp, nonce, encrypt) {
    const sha = crypto.createHash('sha1')
    const arr = [this.token, timestamp, nonce, encrypt].sort()
    sha.update(arr.join(''))
    return sha.digest('hex')
  }
  /**
   * 对密文进行解密
   * @param {String} text    待解密的密文
   */
  decrypt(text) {
    // 创建解密对象，AES采用CBC模式，数据采用PKCS#7填充；IV初始向量大小为16字节，取AESKey前16字节
    const decipher = crypto.createDecipheriv('aes-256-cbc', this.key, this.iv)
    decipher.setAutoPadding(false)

    let deciphered = Buffer.concat([decipher.update(text, 'base64'), decipher.final()])

    deciphered = this.pkcs7.decode(deciphered)
    // 算法：AES_Encrypt[random(16B) + msg_len(4B) + msg + $CorpID]
    // 去除16位随机数
    const content = deciphered.slice(16)
    const length = content.slice(0, 4).readUInt32BE(0)

    return {
      message: content.slice(4, length + 4).toString(),
      appId: content.slice(length + 4).toString()
    }
  }
  /**
   * 对明文进行加密
   * 算法：Base64_Encode(AES_Encrypt[random(16B) + msg_len(4B) + msg + $appId])
   * @param {String} text    待加密明文文本
   */
  encrypt(text) {
    // 16B 随机字符串
    const randomString = crypto.pseudoRandomBytes(16)

    const msg = Buffer.from(text)
    // 获取4B的内容长度的网络字节序
    const msgLength = Buffer.alloc(4)
    msgLength.writeUInt32BE(msg.length, 0)

    const id = Buffer.from(this.appId)

    const bufMsg = Buffer.concat([randomString, msgLength, msg, id])

    // 对明文进行补位操作
    const encoded = this.pkcs7.encode(bufMsg)

    // 创建加密对象，AES采用CBC模式，数据采用PKCS#7填充；IV初始向量大小为16字节，取AESKey前16字节
    const cipher = crypto.createCipheriv('aes-256-cbc', this.key, this.iv)
    cipher.setAutoPadding(false)

    const cipheredMsg = Buffer.concat([cipher.update(encoded), cipher.final()])

    return cipheredMsg.toString('base64')
  }
}

module.exports = WXMsgCrypto


作者：何sir
链接：https://juejin.im/post/5df9e721f265da33c42812df
来源：掘金
著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。
```

## 2.`koa2` 服务端支持 `xml`, `server/index.js`（伪代码）:

```javascript
const xmlParser = require('koa-xml-body')
// 支持xml
app.use(xmlParser({
  key: 'xmlBody', // 将 xml 数据解析到 ctx.request.xmlBody
  xmlOptions: {
    explicitArray: false,
  }
}))
```

注意参数： `explicitArray`，默认值是 `true`，是否将子节点数据放入数组。

```javascript
`<xml>
<MsgId>6197906553041859764</MsgId>
</xml>`
// 当 explicitArray 为 true 时，解析出:
ctx.request.xmlBody // { xml: { MsgId: [ '6197906553041859764' ] } }
// 当为 false 时，解析出:
ctx.request.xmlBody // { xml: { MsgId: '6197906553041859764' } }

```

## 3.加解密使用（伪代码）:

```javascript
// log 用的 log4js 实现，请自行实现对应方法。
const WXMsgCrypto = require('./../util/WXMsgCrypto')
const wxmc = new WXMsgCrypto($Token, $EncodingAESKey, $AppID)


/**
 * 微信回调接口
 * 1、添加 get 方式路由，用来微信验证使用
 * 2、首先添加校验中间件
 * 3、添加 其他 方式路由，用来处理微信回调（消息推送、事件推送等）
 */
router.get('/wxcallback', ctx => {
  log.trace('[get] /wxcallback ctx.request.query:', ctx.request.query)
  let params = ctx.request.query
  ctx.body = params.echostr
})
router.use(async (ctx, next) => {
  if (ctx.request.path === '/api/wechat/wxcallback') {
    // log.trace(`[${ctx.request.method}] ${ctx.request.path}`)
    // log.trace('ctx.request.query', ctx.request.query)
    let query = ctx.request.query
    let xml = ctx.request.xmlBody && ctx.request.xmlBody.xml
    // 校验
    let msgSignature = wxmc.getSignature(query.timestamp, query.nonce, xml.Encrypt)
    if (msgSignature !== query.msg_signature) {
      log.error(`"${ctx.request.method} ${ctx.request.url}\nctx.request.query: ${JSON.stringify(ctx.request.query)}\nctx.request.body: ${JSON.stringify(ctx.request.body)}\nctx.request.xmlBody: ${JSON.stringify(ctx.request.xmlBody)}\n计算出msgSignature:${msgSignature}"`)
      ctx.status = 403
      ctx.body = '失败：验证签名失败。'
    } else {
      await next()
    }
  } else {
    await next()
  }
})
router.all('/wxcallback', ctx => {
  log.trace(`[${ctx.request.method}] /wxcallback ctx.request.xmlBody:`, ctx.request.xmlBody)
  let xml = ctx.request.xmlBody && ctx.request.xmlBody.xml
  // 加密方式为 2 需要解密
  if (config.wechatMessageEncryptMode === '2' && xml) {
    log.trace('进行解密...')
    let xmlSource = wxmc.decrypt(xml.Encrypt)
    log.trace('解密出 xmlSource:', xmlSource)
    // let parser = new xml2js.Parser()
    xml2js.parseString(xmlSource.message, {
      explicitArray: false,
    }, (err, result) => {
      if (err) {
        log.error(`解密发生错误:`, err)
      }
      xml = result.xml
    })
  }
  let result = 'success'
  if (xml) {
    log.trace(`xml:`, xml)
    if (xml.MsgType === 'event') { // 事件推送
      switch (xml.Event) {
        case 'TEMPLATESENDJOBFINISH': // 模板消息发送完成
          log.info('推送事件发送完成：', xml.Status)
          break
      }
    } else if (xml.MsgType === 'text') { // 文本消息
      // 组装返回数据
      let query = ctx.request.query
      let timestamp = new Date().getTime()
      result = `<xml>
          <ToUserName><![CDATA[${xml.FromUserName}]]></ToUserName>
          <FromUserName><![CDATA[${xml.ToUserName}]]></FromUserName>
          <CreateTime>${timestamp}</CreateTime>
          <MsgType><![CDATA[text]]></MsgType>
          <Content><![CDATA[你说的：${xml.Content}]]></Content>
        </xml>`
      // 加密返回数据 并组装 加密后的返回数据
      if (config.wechatMessageEncryptMode === '2') {
        let encryptData = wxmc.encrypt(result)
        // console.log('encryptData', encryptData)
        let msgSignature = wxmc.getSignature(timestamp, query.nonce, encryptData)
        result = `<xml>
          <Encrypt><![CDATA[${encryptData}]]></Encrypt>
          <MsgSignature>${msgSignature}</MsgSignature>
          <TimeStamp>${timestamp}</TimeStamp>
          <Nonce>${query.nonce}</Nonce>
        </xml>`
      }
      log.trace('response xml:', result)
      ctx.res.setHeader('Content-Type', 'application/xml')
    }
  }
  ctx.body = result
})

```

