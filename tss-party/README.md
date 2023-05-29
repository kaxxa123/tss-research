# TSS-LIB Based Threshold Signature Scheme

| [Home](../README.md) |
------------------------

Threshold signature implementation based on Binance’s tss-lib.

This project runs a t-of-n setup saving the signature shares for n participants to disk. 
It also signs a given hash using t+1 signatures shares.

<BR />

## Build

```BASH
cd ./tss-party
go mod tidy
make build
```

<BR />

## Run

The application provides a command line tool for performing a TSS setup and signature generation.

Check the application usage:
```BASH
./bin/tssparty help
```

Application will by default run a 3-of-6 setup and will sign the sha256 for "Hello World!"

To run another setup combination such as 2-of-4, run:
```BASH
./bin/tssparty setup --threshold 2 --party 4
```

To sign the phrase "Secret Sharing" for the same setup run:
```BASH
./bin/tssparty sign --threshold 2 --party 4 --msg "Secret Sharing"
```
<BR />

