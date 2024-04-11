use arrayref::array_ref;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs8::{der::zeroize::Zeroize, EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use rsa::pkcs8::der::zeroize::Zeroizing;
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
pub fn generate_seedphrase() -> Zeroizing<String> {
    // create a new randomly generated mnemonic phrase
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let phrase = mnemonic.phrase().to_owned();

    Zeroizing::new(phrase)
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
pub fn keypair_from_seedphrase(seedphrase: &Zeroizing<String>) -> Result<Keypair, String> {
    match Mnemonic::validate(&seedphrase, Language::English) {
        Ok(_) => (),
        Err(e) => return Err(e.to_string()),
    };
    let mnemonic = Mnemonic::from_phrase(seedphrase.as_str(), Language::English).unwrap();
    let seed = Seed::new(&mnemonic, "");
    let seed_array = array_ref!(seed.as_bytes(), 0, 32);
    let mut rng = ChaCha20Rng::from_seed(*seed_array);
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).map_err(|err| err.to_string())?;
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
pub fn generate_seedphrase_and_keypair() -> Result<(Zeroizing<String>, Keypair), String> {
    let seedphrase = generate_seedphrase();
    let keypair = keypair_from_seedphrase(&seedphrase).map_err(|err| err.to_string())?;

    Ok((seedphrase, keypair))
}

/// exports private key to pkcs1 PEM (Privacy Enhanced Mail) format
///
/// # Examples
/// ```
/// use rsakeygen::generate_seedphrase_and_keypair;
/// use rsakeygen::pkcs1_pem_from_priv_key;
///
/// let (seedphrase, (priv_key, _)) = generate_seedphrase_and_keypair().unwrap();
/// let pem = pkcs1_pem_from_priv_key(&priv_key).unwrap();
/// ```
pub fn pkcs1_pem_from_priv_key(priv_key: &RsaPrivateKey) -> Result<Zeroizing<String>, String> {
    priv_key.to_pkcs1_pem(Default::default())
        .map_err(|err| err.to_string())
}

/// exports public key to pkcs1 PEM (Privacy Enhanced Mail) format
///  
/// # Examples
/// ```
/// use rsakeygen::generate_seedphrase_and_keypair;
/// use rsakeygen::pkcs1_pem_from_pub_key;
///
/// let (seedphrase, (_, pub_key)) = generate_seedphrase_and_keypair().unwrap();
/// let pem = pkcs1_pem_from_pub_key(&pub_key).unwrap();
/// ```
pub fn pkcs1_pem_from_pub_key(pub_key: &RsaPublicKey) -> Result<String, String> {
    pub_key.to_pkcs1_pem(Default::default())
        .map_err(|err| err.to_string())
}

/// exports private key to pkcs8 PEM (Privacy Enhanced Mail) format
///  
/// # Examples
/// ```
/// use rsakeygen::generate_seedphrase_and_keypair;
/// use rsakeygen::pkcs8_from_priv_key;
///
/// let (seedphrase, (priv_key, pub_key)) = generate_seedphrase_and_keypair().unwrap();
/// let pem_key = pkcs8_pem_from_priv_key(&priv_key).unwrap();
/// ```
pub fn pkcs8_pem_from_priv_key(priv_key: &RsaPrivateKey) -> Result<Zeroizing<String>, String> {
    priv_key.to_pkcs8_pem(Default::default())
        .map_err(|err| err.to_string())
}

/// exports public key to pkcs1 PEM (Privacy Enhanced Mail) format
///  
/// # Examples
/// ```
/// use rsakeygen::generate_seedphrase_and_keypair;
/// use rsakeygen::pkcs8_from_pub;
///
/// let (seedphrase, (priv_key, pub_key)) = generate_seedphrase_and_keypair().unwrap();
/// let pem_key = pkcs8_pem_from_pub_key(&pub_key).unwrap();
/// ```
pub fn pkcs8_pem_from_pub_key(pub_key: &RsaPublicKey) -> Result<String, String> {
    pub_key.to_public_key_pem(Default::default())
        .map_err(|err| err.to_string())
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
pub fn store_in_file(keypair: Keypair, seedphrase: &mut Zeroizing<String>, filename: &str) {
    let mut priv_key_pem = pkcs8_pem_from_priv_key(&keypair.0).unwrap();
    let pub_key_pem = pkcs8_pem_from_pub_key(&keypair.1).unwrap();
    let data = format!(
        "Seedphrase: {}\nPrivate Key: {}\nPublic Key: {}",
        seedphrase.as_str(), priv_key_pem.as_str(), pub_key_pem
    );
    priv_key_pem.zeroize();
    seedphrase.zeroize();

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
