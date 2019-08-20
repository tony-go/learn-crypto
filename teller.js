var jsonStream = require('duplex-json-stream')
var net = require('net')
var types = require('./types')

// Get args from command line
var args = process.argv
var [,, command, param] = args


var client = jsonStream(net.connect(2910))

client.on('data', message => {
    console.log('Teller received: ', message)
})

if (command === types.DEPOSIT) {
    client.end({ cmd: command, amount: Number(param) })
}

if (command === types.WITHDRAW) {
    client.end({ cmd: command, amount: Number(param) })
}

if (command === types.BALANCE) {
    client.end({ cmd: command })
}
