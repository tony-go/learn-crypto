const sodium = require('sodium-native')

const secretKey = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)

sodium.randombytes_buf(secretKey)
sodium.randombytes_buf(nonce)

function encrypt (msg) {
    const cipher = Buffer.alloc(msg.length + sodium.crypto_secretbox_MACBYTES)
    const messageBuffer = Buffer.from(msg)
    sodium.crypto_secretbox_easy(cipher, messageBuffer, nonce, secretKey)
    return cipher.toString('hex')
}

function decrypt (cipher) {
    const cipherBuffer = Buffer.from(cipher, 'hex')
    const message = Buffer.alloc(cipher.length - sodium.crypto_secretbox_MACBYTES)
    sodium.crypto_secretbox_open_easy(message, cipherBuffer, nonce, secretKey)
    return message.toString()
}
