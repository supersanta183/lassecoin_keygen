use arrayref::array_ref;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::{pkcs1::EncodeRsaPublicKey, RsaPrivateKey, RsaPublicKey};
use std::fs;

pub struct KeyPair {
    priv_key: RsaPrivateKey,
    pub pub_key: RsaPublicKey,
}

pub struct Keygen {}

impl Keygen {
    pub fn new() -> Self {
        Self {}
    }

    // generates a mnemonic and writes the corresponding seedphrase to seedphrase.txt
    pub fn generate_seedphrase(&self) -> String {
        // create a new randomly generated mnemonic phrase
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let phrase = mnemonic.phrase().to_owned();
        phrase
    }

    pub fn generate_rsa_keypair(&self, seedphrase: &String) -> Result<KeyPair, String> {
        let mnemonic = Mnemonic::from_phrase(seedphrase.as_str(), Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");
        let seed_array = array_ref!(seed.as_bytes(), 0, 32);
        let mut rng = ChaCha20Rng::from_seed(*seed_array);

        let priv_key = match RsaPrivateKey::new(&mut rng, 2048) {
            Ok(x) => x,
            Err(e) => return Err(e.to_string()),
        };
        let pub_key = RsaPublicKey::from(&priv_key);

        Ok(KeyPair { priv_key, pub_key })
    }

    pub fn store_seedphrase(&self, seedphrase: &String, filename: &str) {
        fs::write(filename, seedphrase).expect("failed to write seedphrase to file");
    }

    pub fn store_pub_key(&self, pub_key: RsaPublicKey) {
        pub_key
            .write_pkcs1_pem_file("pubkey.txt", Default::default())
            .expect("failed to write public key to file");
    }

    pub fn generate_keypair_and_write_to_file(&self) -> Result<KeyPair, String> {
        let seedphrase = self.generate_seedphrase();
        self.store_seedphrase(&seedphrase, "seedphrase.txt");

        let KeyPair = match self.generate_rsa_keypair(&seedphrase) {
            Ok(x) => x,
            Err(e) => return Err(e),
        };

        let keypair = self.generate_rsa_keypair(&seedphrase).unwrap();
        let pub_key = keypair.pub_key.to_owned();
        self.store_pub_key(pub_key);

        Ok(keypair)
    }
}

#[test]
fn generate_seedphrase_has_12_words() {
    let keygen = Keygen::new();
    let seedphrase = keygen.generate_seedphrase();
    let words: Vec<&str> = seedphrase.split(" ").collect();

    assert_eq!(words.len(), 12);
}

#[test]
fn generate_keypair_returns_same_pub_key() {
    let keygen = Keygen::new();
    let seedphrase = keygen.generate_seedphrase();
    let keypair = keygen.generate_rsa_keypair(&seedphrase).unwrap();
    let keypair2 = keygen.generate_rsa_keypair(&seedphrase).unwrap();

    assert_eq!(keypair.pub_key, keypair2.pub_key);
}
