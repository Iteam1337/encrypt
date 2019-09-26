interface EncryptOptions {
  algorithm?: string
  authTag?: boolean
  encoding?: string
  iv?: Buffer
  password: string
}

interface EncryptResponse {
  encrypt: (text: string) => string
  decrypt: (text: string) => string
}

export declare function init(options: EncryptOptions | string): EncryptResponse
