mod rsa_keygen;

use rsa::pkcs8::der::zeroize::Zeroizing;
use rsa::signature::Keypair;
use rsa_keygen::generate_seedphrase_and_keypair;
use rsa_keygen::keypair_from_seedphrase;
use rsa_keygen::pkcs8_pem_from_priv_key;


fn main() {
    let sp = String::from("meat morning armed admit salute symptom example total hen tackle skill crawl");
    let zerorized = Zeroizing::new(sp);
    let (seedphrase, keypair) = generate_seedphrase_and_keypair().unwrap();
    let (priv_key, pub_key) = keypair;
    let pem_key = pkcs8_pem_from_priv_key(&priv_key).unwrap();

    //println!("{}", pem_key.as_str());
    println!("{:?}", seedphrase);
}
