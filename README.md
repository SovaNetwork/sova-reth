# Corsa Reth: An extension of reth with Bitcoin precompiles

This configuration of reth's execution client adds a new precompile to the existing list of precompiles in the Cancun hardfork.

The new precompile is found at address 0x999 and accepts a payload of BTC data. The payload specifies the bitcoin rpc call to utilized and the data to send with that rpc call.

## Testing

To test the precompile, use [cast](https://book.getfoundry.sh/reference/cast/transaction-commands) to send an eth call/transaction to the precompile.

Examples for the specific bitcoin rpc call. Each example shows which data prefix to use to each specific bitcoin rpc call.

### sendrawtransaction
> Note: `--data` is prefixed with 0x00. After the prefix is the raw signed btc transaction.
```sh
cast call 0x0000000000000000000000000000000000000999 \
--data 0x0002000000000101b161898f2ef6bd36e1cee4b9d68c5a1937a5001306e81a0fc30e99b44e8f835a00000000000000000001c0aff629010000001600148267b14c9fc90545c5828cbb9d26e12a9ecb8c160247304402205709263844829d625759b202ecf8d85fc6a2c07f958555d5b32c98e9c8b33c8a02200a6132106329e8dcc9c54bc7444075a90f505909bffb63b65f93257cbe23c9040121025912be1b355b604d151f36348c91976c4cda0c3c9c7fcb4469cdf0213fa216e900000000 \
--rpc-url http://localhost:8545
```

### getblockcount
> Note: `--data` is prefixed with 0x01. For btc rpc calls that do not require an input, do not use the `--data` flag. Simply pass the method id. 
```sh
cast call 0x0000000000000000000000000000000000000999 \
0x01 \
--rpc-url http://localhost:8545
```

## Testing Environment

The current `main.rs` file sets the NodeBuilder handle config to 'dev mode'. This means that blocks are automatically mined when a transaction is sent through cast. This should be removed when the chain is used in production.