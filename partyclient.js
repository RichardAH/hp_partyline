//
// HotPocket client example code adopted from:
// https://github.com/codetsunami/hotpocket/blob/master/hp_client.js
//

const fs = require('fs')
const ws_api = require('ws');
const sodium = require('libsodium-wrappers')
const readline = require('readline')

// sodium has a trigger when it's ready, we will wait and execute from there
sodium.ready.then(main).catch((e) => { console.log(e) })

last_seen = ""

function main() {

    var keys = sodium.crypto_sign_keypair()


    // check for client keys
    if (!fs.existsSync('.hp_client_keys')) {
        keys.privateKey = sodium.to_hex(keys.privateKey)
        keys.publicKey = sodium.to_hex(keys.publicKey)
        fs.writeFileSync('.hp_client_keys', JSON.stringify(keys))
    }
    
    keys = JSON.parse(fs.readFileSync('.hp_client_keys'))
    keys.privateKey = Uint8Array.from(Buffer.from(keys.privateKey, 'hex'))
    keys.publicKey = Uint8Array.from(Buffer.from(keys.publicKey, 'hex'))
    

    var server = 'wss://localhost:8080'

    if (process.argv.length == 3) server = 'wss://localhost:' + process.argv[2]

    if (process.argv.length == 4) server = 'wss://' + process.argv[2] + ':' + process.argv[3]

    var ws = new ws_api(server, {
        rejectUnauthorized: false
    })

    /* anatomy of a public challenge
       {
       version: '0.1',
       type: 'public_challenge',
       challenge: '<hex string>'
       }
     */


    // if the console ctrl + c's us we should close ws gracefully
    process.once('SIGINT', function (code) {
        console.log('SIGINT received...');
        ws.close()
    });

    function create_input_container(inp) {
        let inp_container = {
            nonce: (new Date()).getTime().toString(),
            input: Buffer.from(inp).toString('hex'),
            max_ledger_seqno: 9999999
        }
        let inp_container_bytes = JSON.stringify(inp_container);
        let sig_bytes = sodium.crypto_sign_detached(inp_container_bytes, keys.privateKey);

        let signed_inp_container = {
            type: "contract_input",
            content: inp_container_bytes.toString('hex'),
            sig: Buffer.from(sig_bytes).toString('hex')
        }

        return JSON.stringify(signed_inp_container);
    }

    function create_status_request() {
        let statreq = { type: 'stat' }
        return JSON.stringify(statreq);
    }


    ws.on('message', (m) => {

        try {
            m = JSON.parse(m)
        } catch (e) {
            console.log(e)
            return
        }

        //console.log(m);

        if (m.type == 'contract_output' && m.content != '') {
            hex = sodium.from_hex(m.content)
            if (hex.length == 0) return;
            if (hex[0] == 115) {
                //console.log("*message sent*\n")
                return
            }

            if (hex[0] != 114) {
                console.log("*contract sent unknown message*");
                return
            }

    
            start_printing = false
            while (true) {
            // execution to here is raw message records
                for (var i = 1; i < hex.length; i+=256) { // first char of hex is type
                    out = Buffer.from(hex.slice(i+8,i+16)).toString('hex') + ": " + Buffer.from(hex.slice(i+48,i+255)).toString()
                    ts =  Buffer.from(hex.slice(i, i+4)).toString('hex')
                    if (start_printing) {
                        console.log(out)
                        last_seen = ts + out
                    }

                    if (last_seen == ts + out) 
                        start_printing = true
                    
                }

                if (!start_printing)
                    start_printing = true
                else
                    break
            }
            
//            console.log("message from contract: " + hex);
        }

        if (m.type != 'public_challenge') return

        console.log("Received challenge message")
        console.log(m)

        let pkhex = 'ed' + Buffer.from(keys.publicKey).toString('hex');
        console.log('My public key is: ' + pkhex);

        // sign the challenge and send back the response
        var sigbytes = sodium.crypto_sign_detached(m.challenge, keys.privateKey);
        var response = {
            type: 'challenge_resp',
            challenge: m.challenge,
            sig: Buffer.from(sigbytes).toString('hex'),
            pubkey: pkhex
        }

        console.log('Sending challenge response.');
        ws.send(JSON.stringify(response))


        // start listening for stdin
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        // Capture user input from the console.
        var input_pump = () => {
            rl.question('\nProvide an input:\n', (inp) => {

                let msgtosend = "";

                console.log("sending: " + inp)

                if (inp == "stat")
                    msgtosend = create_status_request();
                else
                    msgtosend = create_input_container("m" + inp);
                    
                ws.send(msgtosend)

                
                input_pump()
            })

        }

        ws.send(create_input_container("v0"))
        var readtimer = ()=>{
            ws.send(create_input_container("v0"))
            setTimeout(readtimer, 2000)
        }
        setTimeout(readtimer, 2000)
        input_pump()

        

    });

    ws.on('close', () => {
        console.log('Server disconnected.');
    });
}
