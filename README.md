# aes-encrypt
Some (hopefully) sensible defaults for encrypting in node

The data is serialized using `msgpack5`. This allows for any valid js structure to be encrypted/decrypted

## Install
```bash
npm instal --save aes-encrypt
```

## Use

### Super simple
```javascript
const {encrypt, decrypt} = require('aes-encrypt').init('my super secret password')

const encrypted = encrypt('some text')  // returns a Buffer
const decrypted = decrypt(encrypted)    // returns 'some text'
```

### With options
```javascript
const {encrypt, decrypt} = require('aes-encrypt')
  .init({
    algorithm: 'aes-256-gcm',   // Default is 'aes-256-cbc',
    authTag: true,              // Only works with gcm
    encoding: 'base64',         // Default is null - ie Buffer
    iv: Buffer.alloc(16),       // Not recommended. Sets iv to zeros only. Other, not recommended value is false which removes iv all together
    password: 'some password'
  })

const encrypted = encrypt('some text')  // returns a base64 encoded string
const decrypted = decrypt(encrypted)    // returns 'some text'
```
