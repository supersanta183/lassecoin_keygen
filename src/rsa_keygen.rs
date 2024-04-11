use arrayref::array_ref;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use std::fs;

/// Keypair is a tuple of RSA private key and RSA public key
type Keypair = (RsaPrivateKey, RsaPublicKey);

/// generates a 12 word seedphrase
///
/// # Examples
/// ```
/// use keygen::generate_seedphrase;
/// 
/// let seedphrase = generate_seedphrase();
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
/// use rsakeygen::generate_seedphrase;
/// use rsakeygen::keypair_from_seedphrase;
/// 
/// let seedphrase = generate_seedphrase();
/// let (priv_key, pub_key) = keypair_from_seedphrase(&seedphrase).unwrap();
/// ```
pub fn keypair_from_seedphrase(seedphrase: &String) -> Result<Keypair, String> {
    match Mnemonic::validate(&seedphrase, Language::English) {
        Ok(_) => (),
        Err(e) => return Err(e.to_string()),
    };
    let mnemonic = Mnemonic::from_phrase(seedphrase.as_str(), Language::English).unwrap();
    let seed = Seed::new(&mnemonic, "");
    let seed_array = array_ref!(seed.as_bytes(), 0, 32);
    let mut rng = ChaCha20Rng::from_seed(*seed_array);
    let priv_key = match RsaPrivateKey::new(&mut rng, 2048) {
        Ok(x) => x,
        Err(e) => return Err(e.to_string()),
    };
    let pub_key = RsaPublicKey::from(&priv_key);

    Ok((priv_key, pub_key))
}

/// generates an RSA keypair (private key, public key) with an already known private key
///
/// # Examples
/// ```
/// use rsakeygen::generate_seedphrase_and_keypair;
/// use rsakeygen::keypair_from_private_key;
/// 
/// let (seedphrase, (priv_key, _)) = generate_seedphrase_and_keypair().unwrap();
/// let keypair2 = keypair_from_private_key(&priv_key);
/// ```
pub fn keypair_from_private_key(priv_key: &RsaPrivateKey) -> (RsaPrivateKey, RsaPublicKey) {
    let p = priv_key.clone();
    let pub_key = RsaPublicKey::from(&p);

    (p, pub_key)
}

/// generate a seed phrase and a RSA keypair,
/// seedphrase is stored in seedphrase.txt
/// public key is stored in pubkey.txt
///
/// # Examples
/// ```
/// use rsakeygen::generate_seedphrase_and_keypair;
/// 
/// let (seedphrase, (priv_key, pub_key)) = generate_seedphrase_and_keypair().unwrap();
/// ```
pub fn generate_seedphrase_and_keypair() -> Result<(String, Keypair), String> {
    let seedphrase = generate_seedphrase();
    let keypair = match keypair_from_seedphrase(&seedphrase) {
        Ok(x) => x,
        Err(e) => return Err(e),
    };

    Ok((seedphrase, keypair))
}

/// exports private key to PEM (Privacy Enhanced Mail) format
///
/// # Examples
/// ```
/// use rsakeygen::generate_seedphrase_and_keypair;
/// use rsakeygen::export_private_key_to_pem;
/// 
/// let (seedphrase, (priv_key, _)) = generate_seedphrase_and_keypair().unwrap();
/// export_privatekey_to_pem(&priv_key).unwrap();
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
/// use rsakeygen::generate_seedphrase_and_keypair;
/// use rsakeygen::export_public_key_to_pem;
/// 
/// let (seedphrase, (_, pub_key)) = generate_seedphrase_and_keypair().unwrap();
/// export_privatekey_to_pem(&pub_key).unwrap();
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
/// use rsakeygen::generate_seedphrase_and_keypair;
/// use rsakeygen::store_in_file;
/// 
/// let (seedphrase, keypair) = generate_seedphrase_and_keypair().unwrap();
/// store_in_file(keypair, &seedphrase, "id")
/// ```
pub fn store_in_file(keypair: Keypair, seedphrase: &String, filename: &str) {
    let priv_key_pem = export_private_key_to_pem(&keypair.0).unwrap();
    let pub_key_pem = export_public_key_to_pem(&keypair.1).unwrap();
    let data = format!(
        "Seedphrase: {}\nPrivate Key: {}\nPublic Key: {}",
        seedphrase, priv_key_pem, pub_key_pem
    );

    fs::write(filename, data).expect("failed to write to file");
}

#[test]
fn generate_seedphrase_has_12_words() {
    let seedphrase = generate_seedphrase();
    let words: Vec<&str> = seedphrase.split(" ").collect();

    assert_eq!(words.len(), 12);
}

#[test]
fn generate_keypair_returns_same_pub_key() {
    let seedphrase = generate_seedphrase();
    let (priv_key, pub_key) = keypair_from_seedphrase(&seedphrase).unwrap();
    let (priv_key1, pub_key1) = keypair_from_seedphrase(&seedphrase).unwrap();

    assert_eq!(pub_key, pub_key1);
}

#[test]
fn generate_keypair_returns_same_priv_key() {
    let seedphrase = generate_seedphrase();
    let (priv_key, pub_key) = keypair_from_seedphrase(&seedphrase).unwrap();
    let (priv_key1, pub_key1) = keypair_from_seedphrase(&seedphrase).unwrap();

    assert_eq!(priv_key, priv_key1);
}

#[test]
fn generate_keypair_returns_same_pub_key_from_priv_key() {
    let seedphrase = generate_seedphrase();
    let (priv_key, pub_key) = keypair_from_seedphrase(&seedphrase).unwrap();
    let (priv_key1, pub_key1) = keypair_from_private_key(&priv_key);

    assert_eq!(pub_key, pub_key1);
}
