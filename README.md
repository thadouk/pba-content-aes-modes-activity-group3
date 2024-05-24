Learning implementation of `aes` block cipher that supports `encryption/decryption` over arbitrary data, using three modes:

- ecb
- cbc
- ctr

To verify that roundtrip for each mode is working:
```
cargo t
```
