const sodium = require('sodium-native')

const secretKey = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)

const object = {
    value: {
        cmd: 'deposit',
        amount: 100
    },
    hash: '398839283jdq93992382983982983293828',
    signature: 'sjdf49294932993sdsjdz'
}

sodium.randombytes_buf(secretKey)
sodium.randombytes_buf(nonce)

function encrypt (msg) {
    const cipher = Buffer.alloc(msg.length + sodium.crypto_secretbox_MACBYTES)
    const messageBuffer = Buffer.from(msg, 'utf-8')
    sodium.crypto_secretbox_easy(cipher, messageBuffer, nonce, secretKey)
    return cipher.toString('hex')
}

function decrypt (cipher) {
    const cipherBuffer = Buffer.from(cipher, 'hex')
    const message = Buffer.alloc(cipher.length - sodium.crypto_secretbox_MACBYTES)
    sodium.crypto_secretbox_open_easy(message, cipherBuffer, nonce, secretKey)
    return message.toString('utf-8')
}

// const strObject = JSON.stringify(object)
// console.log(strObject, JSON.parse(strObject).value)

const strObject = JSON.stringify(object, null, 2)
const encryptMessage = encrypt(strObject)
console.log('in ===========>')
console.log(strObject, encryptMessage)
console.log('===========>')

console.log('out ===========>')
const decryptMessage = decrypt(encryptMessage)
console.log('===========>')
console.log(decryptMessage, JSON.parse(decryptMessage))
