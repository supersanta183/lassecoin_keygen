use rand::{rngs::StdRng, SeedableRng};
use random_word::Lang;
use rsa::{pkcs1::EncodeRsaPublicKey, RsaPrivateKey, RsaPublicKey};
use sha2::{Sha256, Digest};
use std::fs;

fn main() {
    let pub_key = generate_pubkey();
    let pem = pub_key
        .to_pkcs1_pem(Default::default())
        .expect("failed to serialize public key");

    fs::write("pubkey.txt", &pem).expect("Unable to write to file");
}

fn generate_pubkey() -> RsaPublicKey {
    //generate seed_phrase
    let seed_phrase = generate_12_word_seed_phrase();

    let priv_key = generate_rsa_from_seed(seed_phrase);
    let pub_key = RsaPublicKey::from(&priv_key);

    pub_key
}

fn generate_rsa_from_seed(seed_phrase: String) -> RsaPrivateKey {

    // Generate a seed from the seed phrase
    let mut hasher = Sha256::new();
    hasher.update(seed_phrase);
    let seed = hasher.finalize();

    // Convert the seed into a byte array of length 32
    let seed_array: [u8; 32] = seed.into();

    // Use the seed to create a random number generator
    let mut rng = StdRng::from_seed(seed_array);

    // Generate the RSA private key
    RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key")
}

fn generate_12_word_seed_phrase() -> String {
    let mut seed_phrase = String::from("");

    for _ in 0..12 {
        let word = random_word::gen(Lang::En);
        seed_phrase.push_str(&word);
        seed_phrase.push_str(" ");
    }
    fs::write("seedphrase.txt", &seed_phrase).expect("Unable to write to file");
    seed_phrase
}
