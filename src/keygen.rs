use arrayref::array_ref;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use std::fs;

/// Keypair is a structure that holds a privatekey and a public key.
pub struct KeyPair {
    pub priv_key: RsaPrivateKey,
    pub pub_key: RsaPublicKey,
}

/// Keygen is used to generate a seedphrase and an RSA keypair
pub struct Keygen {}

impl Keygen {
    /// generate a seed phrase and a RSA keypair,
    /// seedphrase is stored in seedphrase.txt
    /// public key is stored in pubkey.txt
    ///
    /// # Examples
    /// ```
    /// let (seedphrase, keypair) = Keygen::new().unwrap();
    /// ```
    pub fn new() -> Result<(String, KeyPair), String> {
        let seedphrase = Keygen::generate_seedphrase();

        let keypair = match Keygen::from_seedphrase(&seedphrase) {
            Ok(x) => x,
            Err(e) => return Err(e),
        };

        Ok((seedphrase, keypair))
    }

    /// generates a 12 word seedphrase
    ///
    /// # Examples
    /// ```
    /// let seedphrase = Keygen::generate_seedphrase();
    /// ```
    pub fn generate_seedphrase() -> String {
        // create a new randomly generated mnemonic phrase
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let phrase = mnemonic.phrase().to_owned();
        phrase
    }

    /// generates an RSA keypair (private key, public key) with an already known seedphrase
    ///
    /// # Examples
    /// ```
    /// let seedphrase = Keygen::generate_seedphrase();
    /// let keypair = Keygen::from_seedphrase(seedphrase).unwrap();
    /// ```
    pub fn from_seedphrase(seedphrase: &String) -> Result<KeyPair, String> {
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

    /// generates an RSA keypair (private key, public key) with an already known private key
    /// 
    /// # Examples
    /// ```
    /// let (seedphrase, keypair) = Keygen::new().unwrap();
    /// let keypair2 = Keygen::from_private_key(&keypair.priv_key);
    /// ```
    pub fn from_private_key(priv_key: &RsaPrivateKey) -> KeyPair {
        let p = priv_key.clone();
        let pub_key = RsaPublicKey::from(&p);
        KeyPair { priv_key: p, pub_key }
    }
    
    /// exports private key to PEM (Privacy Enhanced Mail) format
    ///
    /// # Examples
    /// ```
    /// let (seedphrase, keypair) = Keygen::new().unwrap();
    /// Keygen::export_privatekey_to_pem(keypair.priv_key);
    /// ```
    pub fn export_private_key_to_pem(priv_key: &RsaPrivateKey) -> Result<String, String> {
        match priv_key.to_pkcs1_pem(Default::default()) {
            Ok(x) => Ok((*x).clone()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// exports public key to PEM (Privacy Enhanced Mail) format
    ///  
    /// # Examples
    /// ```
    /// let (seedphrase, keypair) = Keygen::new();
    /// Keygen::export_privatekey_to_pem(keypair.pub_key);
    /// ```
    pub fn export_public_key_to_pem(pub_key: &RsaPublicKey) -> Result<String, String> {
        match pub_key.to_pkcs1_pem(Default::default()) {
            Ok(x) => Ok(x),
            Err(e) => Err(e.to_string()),
        }
    }

    /// stores a seedphrase and keypair in a file with name filename.txt
    ///
    /// # Examples
    /// ```
    /// let (seedphrase, keypair) = Keygen::new().unwrap();
    /// Keygen::store_in_file(keypair, &seedphrase, "id")
    /// ```
    pub fn store_in_file(keypair: KeyPair, seedphrase: &String, filename: &str) {
        let priv_key_pem = Keygen::export_private_key_to_pem(&keypair.priv_key).unwrap();
        let pub_key_pem = Keygen::export_public_key_to_pem(&keypair.pub_key).unwrap();

        let data = format!(
            "Seedphrase: {}\nPrivate Key: {}\nPublic Key: {}",
            seedphrase, priv_key_pem, pub_key_pem
        );

        fs::write(filename, data).expect("failed to write to file");
    }
}

#[test]
fn generate_seedphrase_has_12_words() {
    let seedphrase = Keygen::generate_seedphrase();
    let words: Vec<&str> = seedphrase.split(" ").collect();

    assert_eq!(words.len(), 12);
}

#[test]
fn generate_keypair_returns_same_pub_key() {
    let seedphrase = Keygen::generate_seedphrase();
    let keypair = Keygen::from_seedphrase(&seedphrase).unwrap();
    let keypair2 = Keygen::from_seedphrase(&seedphrase).unwrap();

    assert_eq!(keypair.pub_key, keypair2.pub_key);
}
