mod rsa_keygen;

use bip39::Mnemonic;
use rsa::pkcs8::der::zeroize::Zeroizing;
use rsa::signature::Keypair;
use rsa_keygen::generate_seedphrase_and_keypair;
use rsa_keygen::seedphrase_from_password;
use rsa_keygen::keypair_from_seedphrase;
use rsa_keygen::pkcs8_pem_from_priv_key;
use rsa_keygen::pkcs8_pem_from_pub_key;


fn main() {
    let sp = String::from("meat morning armed admit salute symptom example total hen tackle skill crawl");
    let zerorized = Zeroizing::new(sp);
    let (seedphrase, keypair) = generate_seedphrase_and_keypair().unwrap();
    let (priv_key, pub_key) = keypair;
    let pem_key = pkcs8_pem_from_priv_key(&priv_key).unwrap();

    let password = Zeroizing::from(String::from("Emil er sej"));
    let mnemonic = seedphrase_from_password(&password);

    println!("{:?}", mnemonic);




    //println!("{}", pem_key.as_str());
    println!("{:?}", seedphrase);
}
