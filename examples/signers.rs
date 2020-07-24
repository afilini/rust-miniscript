extern crate bitcoin;
extern crate miniscript;

use std::str::FromStr;

use miniscript::descriptor::DescriptorKeyWithSecrets;
use miniscript::signer::*;

fn main() {
    let DescriptorWithSigners { descriptor, signers } = miniscript::signer::DescriptorWithSigners::<DescriptorKeyWithSecrets>::from_str(
        "wsh(c:pk_k(xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73/44'/0'/0'/0/1/2/*))",
    )
    .unwrap();

    println!("{}", descriptor);

    println!("{:?}", signers.ids());
    println!("{:#?}", descriptor);
}
