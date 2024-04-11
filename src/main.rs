mod keygen;

use keygen::Keygen;

fn main() {
    let keygen = Keygen::new();
    //let Keypair = keygen.generate_keypair_and_write_to_file();

    let keygen = Keygen::new();
    let seedphrase = keygen.generate_seedphrase();
    println!("{}", seedphrase);
}
