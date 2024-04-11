# rsa_keygen

## How to use:
A keypair is a struct where the first element is the private key and the second element is the public key:
```Rust
type Keypair = (RsaPrivateKey, RsaPublicKey);
```

```Rust
pub use rsa_keygen::generate_seedphrase;
pub use rsa_keygen::keypair_from_seedphrase;
pub use rsa_keygen::keypair_from_private_key;
pub use rsa_keygen::generate_seedphrase_and_keypair;
pub use rsa_keygen::export_private_key_to_pem;
pub use rsa_keygen::export_public_key_to_pem;
pub use rsa_keygen::store_in_file;

//generate a 12 word seedphrase
let seedphrase = generate_seedphrase();

//generate an rsa keypair from the 12 word seedphrase
let (priv_key, pub_key) = keypair_from_seedphrase(&seedphrase).unwrap();

//generate an rsa keypair from an already known secret key
let (priv_key, pub_key) = keypair_from_private_key(&keypair.priv_key);
```

you can generate the seedphrase and keypair easily using the generate_seedphrase_and_keypair function:
```Rust
let (seedphrase, keypair) = generate_seedphrase_and_keypair().unwrap();
```

you can export the private key or the public key to pem format in order to make it more readable, using the export functions:
```Rust 
let pub_key_pem = export_public_key_to_pem(&keypair.pub_key).unwrap();
let priv_key_pem = export_private_key_to_pem(&keypair.priv_key).unwrap();
```

it's possible to write the keypair and seedphrase to a file using the store_in_file function:
```Rust
store_in_file(keypair, &seedphrase, "id.txt");
```


**If you have any requests or improvements, make an issue or a pr on the github.**