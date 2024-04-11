mod rsa_keygen;

use std::hash::{DefaultHasher, Hash, Hasher};

use bip39::{Language, Mnemonic, MnemonicType, Seed};

use rsa_keygen::generate_seedphrase_and_keypair;

fn main() {
    let (seedphrase, keypair) = generate_seedphrase_and_keypair().unwrap();
    let i = "day road engine best spike witness custom heart damage security matter mouse";
    //let words = Mnemonic::from_phrase(i, Language::English).unwrap();
}
