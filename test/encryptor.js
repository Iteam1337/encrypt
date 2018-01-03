const {expect} = require('chai')
const {init, encrypt, decrypt, deserialize} = require(`${process.cwd()}/lib/encryptor`)
const {readFile} = require('fs')

describe('encryptor', () => {
  let password, message
  beforeEach(() => {
    password = 'Some stupid password'
    message = 'Som string that I want to encrypt'
  })
  describe('defaults', () => {
    describe('encrypt', () => {
      it('throws if no password is set', () => {
        expect(() => encrypt(message))
          .to.throw(Error)
      })
      it('sets correct defaults', () => {
        const encrypted = encrypt(message, {password})
        const envelope = deserialize(encrypted)
        expect(envelope.algorithm, 'envelope.algorithm')
          .to.equal('aes-256-cbc')
        expect(envelope.iv, 'envelope.iv')
          .to.be.instanceof(Buffer)
          .and.have.length(16)
        expect(envelope.content, 'envelope.content')
          .to.be.instanceof(Buffer)
        expect(envelope.authTag, 'envelope.authTag')
          .to.not.exist
      })
    })
    describe('decrypt', () => {
      it('throws if no password is set', () => {
        expect(() => decrypt(message))
          .to.throw(Error)
      })
      it('decrypts correctly', () => {
        const encrypted = encrypt(message, {password})
        expect(decrypt(encrypted, password))
          .to.equal(message)
      })
    })
  })
  describe('init', () => {
    it('throws if no password is provided', () => {
      expect(() => init({})).to.throw(Error)
    })
    describe('password only', () => {
      let instance
      beforeEach(() => {
        instance = init(password)
      })
      it('encrypts with correct defaults', () => {
        const encrypted = instance.encrypt(message)
        const envelope = deserialize(encrypted)
        expect(envelope.algorithm, 'envelope.algorithm')
          .to.equal('aes-256-cbc')
        expect(envelope.iv, 'envelope.iv')
          .to.be.instanceof(Buffer)
          .and.have.length(16)
        expect(envelope.content, 'envelope.content')
          .to.be.instanceof(Buffer)
        expect(envelope.authTag, 'envelope.authTag')
          .to.not.exist
      })
      it('encrypts with different results', () => {
        const encrypted1 = instance.encrypt(message)
        const encrypted2 = instance.encrypt(message)
        expect(encrypted1)
          .to.not.equal(encrypted2)
      })
      it('decrypts correctly', () => {
        const encrypted = instance.encrypt(message)
        expect(instance.decrypt(encrypted))
          .to.equal(message)
      })
    })
    describe('no iv', () => {
      let instance
      beforeEach(() => {
        instance = init({
          password,
          iv: false
        })
      })
      it('encrypts with correct defaults', () => {
        const encrypted = instance.encrypt(message)
        const envelope = deserialize(encrypted)
        expect(envelope.algorithm, 'envelope.algorithm')
          .to.equal('aes-256-cbc')
        expect(envelope.iv, 'envelope.iv')
          .to.not.exist
        expect(envelope.content, 'envelope.content')
          .to.be.instanceof(Buffer)
        expect(envelope.authTag, 'envelope.authTag')
          .to.not.exist
      })
      it('encrypts with identical results', () => {
        const encrypted1 = instance.encrypt(message, {encoding: 'base64'})
        const encrypted2 = instance.encrypt(message, {encoding: 'base64'})
        expect(encrypted1)
          .to.equal(encrypted2)
      })
      it('decrypts correctly', () => {
        const encrypted = instance.encrypt(message)
        expect(instance.decrypt(encrypted))
          .to.equal(message)
      })
    })
    describe('fixed iv', () => {
      let instance
      beforeEach(() => {
        instance = init({
          password,
          iv: Buffer.alloc(16)
        })
      })
      it('encrypts with correct defaults', () => {
        const encrypted = instance.encrypt(message)
        const envelope = deserialize(encrypted)
        expect(envelope.algorithm, 'envelope.algorithm')
          .to.equal('aes-256-cbc')
        expect(envelope.iv, 'envelope.iv')
          .to.be.instanceof(Buffer)
          .and.have.length(16)
        expect(envelope.content, 'envelope.content')
          .to.be.instanceof(Buffer)
        expect(envelope.authTag, 'envelope.authTag')
          .to.not.exist
      })
      it('encrypts with identical results', () => {
        const encrypted1 = instance.encrypt(message, {encoding: 'base64'})
        const encrypted2 = instance.encrypt(message, {encoding: 'base64'})
        expect(encrypted1)
          .to.equal(encrypted2)
      })
      it('decrypts correctly', () => {
        const encrypted = instance.encrypt(message)
        expect(instance.decrypt(encrypted))
          .to.equal(message)
      })
    })
    describe('gcm with auth tag', () => {
      let instance
      beforeEach(() => {
        instance = init({
          password,
          algorithm: 'aes-256-gcm',
          authTag: true
        })
      })
      it('encrypts with correct defaults', () => {
        const encrypted = instance.encrypt(message)
        const envelope = deserialize(encrypted)
        expect(envelope.algorithm, 'envelope.algorithm')
          .to.equal('aes-256-gcm')
        expect(envelope.iv, 'envelope.iv')
          .to.be.instanceof(Buffer)
          .and.have.length(16)
        expect(envelope.content, 'envelope.content')
          .to.be.instanceof(Buffer)
        expect(envelope.authTag, 'envelope.authTag')
          .to.be.instanceof(Buffer)
      })
      it('decrypts correctly', () => {
        const encrypted = instance.encrypt(message)
        expect(instance.decrypt(encrypted))
          .to.equal(message)
      })
    })
    describe('as base64 string', () => {
      let instance
      beforeEach(() => {
        instance = init({
          password,
          encoding: 'base64'
        })
      })
      it('encrypts with correct defaults', () => {
        const encrypted = instance.encrypt(message)
        expect(encrypted)
          .to.be.a('string')

        const envelope = deserialize(encrypted)
        expect(envelope.algorithm, 'envelope.algorithm')
          .to.equal('aes-256-cbc')
        expect(envelope.iv, 'envelope.iv')
          .to.be.instanceof(Buffer)
          .and.have.length(16)
        expect(envelope.content, 'envelope.content')
          .to.be.instanceof(Buffer)
        expect(envelope.authTag, 'envelope.authTag')
          .to.not.exist
      })
      it('decrypts correctly', () => {
        const encrypted = instance.encrypt(message)
        expect(instance.decrypt(encrypted))
          .to.equal(message)
      })
    })
    describe('large text', () => {
      let text
      beforeEach((done) => {
        instance = init({
          password,
          encoding: 'base64'
        })
        readFile(`${process.cwd()}/test/lorem-ipsum.txt`, {encoding: 'utf8'}, (err, doc) => {
          if (err) {
            done(err)
          } else {
            text = doc
            done()
          }
        })
      })
      it('encrypts and decrypts', () => {
        const encrypted = instance.encrypt(text)
        const decrypted = instance.decrypt(encrypted)

        expect(encrypted)
          .to.be.a('string')
        expect(decrypted)
          .to.equal(text)
      })
    })
  })
})
