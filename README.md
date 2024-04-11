# rsa_keygen

## How to use:
``` Rust
use rsa_keygen::Keygen;

//generate a 12 word seedphrase
let seedphrase = Keygen::generate_seedphrase();

//generate an rsa keypair from the 12 word seedphrase
let keypair = Keygen::from_seedphrase(&seedphrase).unwrap();

//generate an rsa keypair from an already known secret key
let keypair = Keygen::from_private_key(&keypair.priv_key);
```

you can generate the seedphrase and keypair easily using the new function:
``` Rust
let (seedphrase, keypair) = Keygen::new().unwrap();
```

you can export the private key or the public key to pem format in order to make it more readable, using the export functions:
``` Rust 
let pub_key_pem = Keygen::export_public_key_to_pem(&keypair.pub_key).unwrap();
let priv_key_pem = keygen::export_private_key_to_pem(&keypair.priv_key).unwrap();
```

it's possible to write the keypair and seedphrase to a file using the store_in_file function:
``` Rust
Keygen::store_in_file(keypair, &seedphrase, "id.txt");
```


If you have any requests or improvements, make an issue or a pr on the github.