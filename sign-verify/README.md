# Signature Verifier

| [Home](../README.md) |
------------------------

A little node.js app to verify secp256k1 signatures.

<BR />

## Build

```BASH
cd ./sign-verify
npm i
npm run build
npm run test
```

<BR />

## Run

To verify a signature from the execution of ``tss-party``,  grab the following values from the log of the signing command: ``Uncompressed PubKey``, ``Message``, ``Signature R`` and ``Signature S``.

```BASH
...
Uncompressed PubKey: 0x04ccbf7eca314be64f90a4fd2bdd23410c3e1cacb8f9b88ef0cefb9061e596b5d0b9b6787bef0837d62de6a192f6b9c54afc6a6479946008f3e8fc647bedd044e8
...
ECDSA signature Verified
Message:     Secret Sharing
Msg Hash:    ca1767a86cdff90c45f532d3697582d4e2579ed80045806cd090899499f6051e
Signature V: 27
Signature R: cb52cabdb57019cf522092dfc5f73aa1db0fa19e614156b9c0d37f780966ad21
Signature S: 9198866b419ab7d25d88ce4609bba8339fd97ea708bd7e125a14c3bd30545c1
```

Next check the parameters:

```bash
node ./build/src/sign verify --help
```

To verify the above signature:
```bash
node ./build/src/sign  verify  \
  --pk 0x04ccbf7eca314be64f90a4fd2bdd23410c3e1cacb8f9b88ef0cefb9061e596b5d0b9b6787bef0837d62de6a192f6b9c54afc6a6479946008f3e8fc647bedd044e8  \
  --signR cb52cabdb57019cf522092dfc5f73aa1db0fa19e614156b9c0d37f780966ad21  \
  --signS 9198866b419ab7d25d88ce4609bba8339fd97ea708bd7e125a14c3bd30545c1  \
  --msg  "Secret Sharing"
```

This should return:
```BASH
Signature Valid!
```
