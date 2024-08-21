# Corsa Reth: An extension of reth with Bitcoin precompiles

This configuration of reth's execution client adds a new precompile to the existing list of precompiles in the Cancun hardfork.

The new precompile is found at address 0x99 and accepts a payload of BTC data. The payload specifies the bitcoin rpc call to utilized and the data to send with that rpc call.