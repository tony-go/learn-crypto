var fs = require('fs')
var net = require('net')
var jsonStream = require('duplex-json-stream')
var sodium = require('sodium-native')

var types = require('./types'),
    seprator = '/:sep/',
    transactions = [],
    state, // rename to balance
    keyPair,
    nonce,
    key,
    stringLogs

/*
* $$$$$
* UTILS
* $$$$$
*/

function computeState (logs) {
    return logs.reduce((acc, curr) => {
        if (curr.value.cmd === types.DEPOSIT) {
            acc += curr.value.amount
        }
        if (curr.value.cmd === types.WITHDRAW) {
            acc -= curr.value.amount
        }
        return acc
    }, 0)
}

function checkIntegrity (logs) {
    function verifyTransaction(signature, hash) {
        var bufferSignature = Buffer.from(signature, 'hex')
        var hashBuffer = Buffer.from(hash, 'hex')
        var publicKey = Buffer.from(keyPair.publicKey, 'hex')
        return sodium.crypto_sign_verify_detached(bufferSignature, hashBuffer, publicKey)
    }

    var prevHash = null;
    return !logs.find(log => {
        const isHashValid = prevHash
            ? log.hash === getHash(prevHash + JSON.stringify(log.value))
            : log.hash === getHash(getGenesisHash() + JSON.stringify(log.value))
        const isVerify = verifyTransaction(log.signature, log.hash)
        prevHash = log.hash
        return !isHashValid || !isVerify
    })
}

function getKeyPair() {
    var publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    var secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

    sodium.crypto_sign_keypair(publicKey, secretKey)
    return {
        publicKey: publicKey.toString('hex'),
        secretKey: secretKey.toString('hex')
    }
}

function getGenesisHash () {
    return Buffer.alloc(sodium.crypto_generichash_BYTES)
        .toString('hex')
}

function getHash (string) {
    var input = Buffer.from(string)
    var output = Buffer.alloc(sodium.crypto_generichash_BYTES)
    sodium.crypto_generichash(output, input)
    return output.toString('hex')
}

function signTransaction(entry) {
    if (!entry.hash || !keyPair.secretKey) return
    var signature = Buffer.alloc(sodium.crypto_sign_BYTES)
    var message = Buffer.from(entry.hash, 'hex')
    var key = Buffer.from(keyPair.secretKey, 'hex')
    sodium.crypto_sign_detached(signature, message, key)
    return {
        ...entry,
        signature: signature.toString('hex')
    }
}

function enrichLogEntry (entry) {
    var prevHash = transactions.length
        ? transactions[transactions.length - 1].hash
        : getGenesisHash()
    var newEntry = {
        value: entry,
        hash: getHash(prevHash + JSON.stringify(entry))
    }
    return signTransaction(newEntry);
}

function convertLog(logs) {
    const splitLog = logs.split(seprator)
    const res = []
    console.log('0', typeof splitLog[0], splitLog[0])
    splitLog.forEach((log, index) => {
        if (log !== undefined || log !== null || log !== '') {
            res.push(log)
        }
    })
    return []
}

function encrypt (message) {
    const cipher = Buffer.alloc(message.length + sodium.crypto_secretbox_MACBYTES)
    const messageBuffer = Buffer.from(message)
    const nonceBuffer = Buffer.from(nonce, 'hex')
    const keyBuffer = Buffer.from(key, 'hex')
    sodium.crypto_secretbox_easy(cipher, messageBuffer, nonceBuffer, keyBuffer)
    return cipher.toString('hex')
}

function decrypt (cipher) {
    const cipherBuffer = Buffer.from(cipher, 'hex')
    const message = Buffer.alloc(cipher.length - sodium.crypto_secretbox_MACBYTES)
    const nonceBuffer = Buffer.from(nonce, 'hex')
    const keyBuffer = Buffer.from(key, 'hex')
    const isDecrypt = sodium.crypto_secretbox_open_easy(message, cipherBuffer, nonceBuffer, keyBuffer)
    return isDecrypt ? message.toString() : []
}

function getRandomKey () {
    const secretKey = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
    sodium.randombytes_buf(secretKey)
    return secretKey.toString('hex')
}

function getNonce() {
    const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
    sodium.randombytes_buf(nonce)
    return nonce.toString('hex')
}

/*
* $$$$$$$
* BANK DB
* $$$$$$$
*/

function setDB () {
    fs.readFile('./db.json', 'utf-8', (err, data) => {
        if (err) {
            fs.writeFileSync('db.json', JSON.stringify({
                logs: '',
                keyPair: getKeyPair(),
                key: getRandomKey(),
                nonce: getNonce()
            }, null, 2))
            setDB()
            return;
        }
        const { logs, keyPair: storedKeyPair, key: storedKey, nonce: storedNonce } = JSON.parse(data)

        // set keyPair / key / nonce
        keyPair = storedKeyPair
        key = storedKey
        nonce = storedNonce

        // set transactions and set balanc
        stringLogs = logs.length ? decrypt(logs) : null
        transactions = stringLogs ? convertLog(stringLogs) : [] // convert to an array
        state = computeState(transactions)

        // check log's integrity
        const isLogsUpright = checkIntegrity(transactions)
        if (isLogsUpright) {
            console.log('Bank is ready !')
        } else {
            console.log('Error: DB was tampered')
            process.exit()
        }
    })
}

function save () {
    console.log(stringLogs);
    fs.readFile('./db.json', 'utf-8', (err, data) => {
        if (err) {
            console.log(err)
            console.error('DB encounter a problem')
        }
        const { keyPair, key, nonce } = JSON.parse(data);
        fs.writeFileSync('db.json', JSON.stringify({ logs: encrypt(stringLogs), keyPair, key, nonce }, null, 2))
    })
}


/*
* $$$$$$$$$$$
* BANK SERVER
* $$$$$$$$$$$
*/


var server = net.createServer(socket => {
    socket = jsonStream(socket)

    function emitBalance () {
        state = computeState(transactions)
        socket.write({ cmd: types.BALANCE, blance: state})
    }

    socket.on('data', message => {
        console.log('Bank received: ', message)
        if (!message.cmd) return
        switch (message.cmd) {
            case types.BALANCE:
                socket.write({ cmd: types.BALANCE, balance: state })
                break
            case types.DEPOSIT:
                const enrichMessage = enrichLogEntry(message)
                transactions.push(enrichMessage)
                stringLogs = stringLogs ? `${stringLogs}${JSON.stringify(enrichMessage)}${seprator}` : `${JSON.stringify(enrichMessage)}`
                emitBalance()
                break
            case types.WITHDRAW:
                if (message.amount && !(computeState(transactions) - message.amount)) {
                    socket.write({ error: 'Not enough cash in the bank'})
                    break
                }
                transactions.push(enrichLogEntry(message))
                emitBalance()
                break
            default:
                socket.write({ error: 'command not found'})
                break
        }
        save()
    })

})

server.listen(2910, () => {
    console.log('Bank is loading ...')
    setDB()
})
