mod keygen;

use keygen::Keygen;


fn main() {
    let (seedphrase, keypair) = Keygen::generate_seedphrase_and_rsa_keypair().unwrap();
    Keygen::store_in_file(keypair, &seedphrase, "id");
}
