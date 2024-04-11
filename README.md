# rsa_keygen

## How to use:
``` Rust
use rsa_keygen::Keygen

//generate a 12 word seedphrase
let seedphrase = Keygen::generate_seedphrase();

//generate an rsa keypair from the 12 word seedphrase
let keypair = Keygen::generate_rsa_keypair(&seedphrase).unwrap();
```

you can generate the seedphrase and keypair easily using the generate_seedphrase_and_rsa_keypair function:
``` Rust
let (seedphrase, keypair) = Keygen::generate_seedphrase_and_rsa_keypair().unwrap();
```

you can export the private key or the public key to pem format in order to make it more readable, using the export functions:
``` Rust 
let pub_key_pem = Keygen::export_public_key_to_pem(&keypair.pub_key);
let priv_key_pem = keygen::export_private_key_to_pem(&keypair.priv_key)
```

it's possible to write the keypair and seedphrase to a file using the store_in_file function:
``` Rust
Keygen::store_in_file(keypair, &seedphrase, "id.txt");
```
