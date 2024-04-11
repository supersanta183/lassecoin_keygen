mod keygen;

use rsa_keygen::Keygen;


fn main() {
    let (seedphrase, keypair) = Keygen::new().unwrap();
    Keygen::store_in_file(keypair, &seedphrase, "id");
}
