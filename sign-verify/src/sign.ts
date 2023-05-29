import * as yargs from 'yargs'
import { createHash } from 'crypto'
const  { ecdsaVerify } = require('secp256k1')

const UNCOMP_PK_LEN = 64+64+2;

yargs.version("1.1.0")

const pkOption: yargs.Options = {
    describe: "uncompressed public key (hex)",
    demandOption: true,
    type: "string"
}

const signROption: yargs.Options = {
    describe: "Signature R value (hex)",
    demandOption: true,
    type: "string"
}

const signSOption: yargs.Options = {
    describe: "Signature R value (hex)",
    demandOption: true,
    type: "string"
}

const msgOption: yargs.Options = {
    describe: "Message whose sha256 was signed (text)",
    demandOption: true,
    type: "string"
}

function strip0x(v: string): string {
    return v.replace(/^0x/, "");
}

function verifySignature(pk: string, signR: string, signS: string, msg: string): boolean {

    signR = strip0x(signR)
    signS = strip0x(signS)
    pk    = strip0x(pk)

    if (pk.length != UNCOMP_PK_LEN)
        throw `Invalid uncompressed public key length. Required len: ${UNCOMP_PK_LEN}`

    if (signR.length < 64) 
        signR = signR.padStart(64-signR.length, '0')

    if (signS.length < 64) 
        signS = signS.padStart(64-signS.length, '0')

    const sign      = signR + signS;
    const sigBuffer = Buffer.from(sign, 'hex');
    const pkBuffer  = Buffer.from(pk, 'hex');
    const msgHash   = createHash('sha256').update(msg).digest();

    // Verify the signature
    const result = ecdsaVerify(sigBuffer, msgHash, pkBuffer);

    return result;
}

yargs.command({
    command: "verify",
    describe: "verify signature",
    builder: {
        pk:     pkOption,
        signR:  signROption,
        signS:  signSOption,
        msg:    msgOption
    },
    handler: function (argv: any) {
        const isVerified = verifySignature(argv.pk, argv.signR, argv.signS, argv.msg);

        if (isVerified)
            console.log('Signature Valid!');
        else 
            console.log('Signature NOT Valid!');
    }
});

try {
    yargs.parse();
}
catch (err) {
    console.log(err)
}
