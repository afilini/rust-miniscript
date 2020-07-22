extern crate bitcoin;
extern crate miniscript;

use std::str::FromStr;

use miniscript::descriptor::DescriptorKeyWithSecrets;
use miniscript::miniscript::signer::MiniscriptWithSigners;
use miniscript::Legacy;

fn main() {
    let MiniscriptWithSigners { miniscript, signers } = miniscript::miniscript::signer::MiniscriptWithSigners::<DescriptorKeyWithSecrets, Legacy>::from_str(
        "c:pk_k(xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73/0/1/2/*)",
    )
    .unwrap();

    println!("{}", miniscript);

    println!("{:?}", signers.ids());
    println!("{:#?}", miniscript);
}
