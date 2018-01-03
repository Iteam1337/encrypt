const {
  createCipher,
  createCipheriv,
  createDecipher,
  createDecipheriv,
  createHash,
  randomBytes
} = require('crypto')

const {encode, decode} = require('msgpack5')()

const defaults = {
  algorithm: 'aes-256-cbc',
  iv: true,
  authTag: false
}

function encrypt (content, options = {}) {
  if (typeof options === 'string') {
    options = {password: options}
  }
  options = Object.assign({}, defaults, options)
  if (!options.password) {
    throw new Error('Password required')
  }
  const password = createHash('sha256').update(options.password).digest()
  const result = {algorithm: options.algorithm}
  let cipher
  if (options.iv !== false) {
    result.iv = (options.iv instanceof Buffer) ? options.iv : randomBytes(16)
    cipher = createCipheriv(result.algorithm, password, result.iv)
  } else {
    cipher = createCipher(result.algorithm, password)
  }
  const [buf1, buf2] = [cipher.update(encode(content).slice()), cipher.final()]
  result.content = Buffer.concat([buf1, buf2], buf1.length + buf2.length)
  if (options.authTag) {
    result.authTag = cipher.getAuthTag()
  }
  return serialize(result, options.encoding)
}

function decrypt (encrypted, password) {
  if (!password) {
    throw new Error('Password required')
  }
  password = createHash('sha256').update(password).digest()
  const obj = deserialize(encrypted)
  let decipher
  if (obj.iv) {
    decipher = createDecipheriv(obj.algorithm, password, obj.iv)
  } else {
    decipher = createDecipher(obj.algorithm, password)
  }
  if (obj.authTag) {
    decipher.setAuthTag(obj.authTag)
  }
  const [buf1, buf2] = [decipher.update(obj.content), decipher.final()]
  const content = Buffer.concat([buf1, buf2], buf1.length + buf2.length)
  return decode(content)
}

function serialize (obj, encoding) {
  const binary = encode(obj).slice()
  return (encoding) ? binary.toString(encoding) : binary
}

function deserialize (content, encoding = 'base64') {
  if (typeof content === 'string') {
    content = Buffer.from(content, encoding)
  }
  return decode(content)
}

function init (options = {}) {
  if (typeof options === 'string') {
    options = {password: options}
  }
  if (!options.password) {
    throw new Error('Password required')
  }
  options = Object.assign({}, defaults, options)
  return {
    encrypt: (text, opts = {}) => encrypt(text, Object.assign({}, options, opts)),
    decrypt: (encrypted) => decrypt(encrypted, options.password)
  }
}

module.exports = {init, encrypt, decrypt, serialize, deserialize}
