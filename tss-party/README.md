# TSS-LIB Based Threshold Signature Scheme

Threshold signature implementation based on Binance’s tss-lib.

This project runs a t-of-n setup saving the signature shares for n participants to disk. 
It also signs a given hash using t+1 signatures shares.

<BR />

## Building

```BASH
cd ./tss-party
go mod tidy
make build
```

<BR />

## Running

The application provides a command line tool for performing a TSS setup and signature generation.

Check the application usage:
```BASH
./bin/tssparty help
```

<BR />

