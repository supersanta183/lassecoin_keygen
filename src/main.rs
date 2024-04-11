mod rsa_keygen;

use rsa_keygen::generate_seedphrase_and_keypair;


fn main() {
    let (seedphrase, keypair) = generate_seedphrase_and_keypair().unwrap();
    let (priv_key, pub_key) = keypair;
}
