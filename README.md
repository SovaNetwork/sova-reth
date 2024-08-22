# Corsa Reth: An extension of reth with Bitcoin precompiles

This configuration of reth's execution client adds a new precompile to the existing list of precompiles in the Cancun hardfork.

The new precompile is found at address 0x999 and accepts a payload of BTC data. The payload specifies the bitcoin rpc call to utilized and the data to send with that rpc call.

## Testing

To test the precompile, use [cast](https://book.getfoundry.sh/reference/cast/transaction-commands) to send transaction to the precompile.

For example:

```
cast call 0x0000000000000000000000000000000000000999 \
  --rpc-url http://localhost:8545 \
  --data 0x020000000001014b77e56ef64607a34ea6bb54bd39f75e70c7eac183765db6b797661048861f1900000000000000000001c0aff629010000001600148267b14c9fc90545c5828cbb9d26e12a9ecb8c16024730440220442b52f30dcf68757dd98766db22ef8d8b18ad52c5b7787beef497399877b2f00220012ac5aadadafa926a7b1a97f18a5d1080631d53a6593b9c1521516b1a7736340121025912be1b355b604d151f36348c91976c4cda0c3c9c7fcb4469cdf0213fa216e900000000
0x66393762396264623066326333663836393165323735363830613630633430663265663434616436366631306236356662353934633035643830356365343666
```
The `--data` param here is the signed bitcoin tx.

### Testing Environment

The current `main.rs` file sets the NodeBuilder handle config to 'dev mode'. This means that blocks are automatically mined when a transaction is sent through cast. This should be removed when the chain is used in production.