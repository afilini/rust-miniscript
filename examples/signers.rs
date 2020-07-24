extern crate bitcoin;
extern crate miniscript;

use std::str::FromStr;
use std::sync::Arc;

use miniscript::descriptor::DescriptorKeyWithSecrets;
use miniscript::signer::*;

use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::hex::FromHex;

fn main() {
    let DescriptorWithSigners {
        descriptor,
        signers,
    } = miniscript::signer::DescriptorWithSigners::<DescriptorKeyWithSecrets>::from_str(
        "wpkh(L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6)",
    )
    .unwrap();
    println!("{}", descriptor);

    let psbt: bitcoin::util::psbt::PartiallySignedTransaction = deserialize(&Vec::<u8>::from_hex("70736274ff010052020000000162307be8e431fbaff807cdf9cdc3fde44d740211bc8342c31ffd6ec11fe35bcc0100000000ffffffff01328601000000000016001493ce48570b55c42c2af816aeaba06cfee1224fae000000000001011fa08601000000000016001493ce48570b55c42c2af816aeaba06cfee1224fae010304010000000000").unwrap()).unwrap();
    println!("{:?}", psbt);

    let mut txin = psbt.global.unsigned_tx.input[0].clone();

    let signing_ctx = PSBTSigningContext {
        psbt: &psbt,
        input_index: 0,
        signers: Arc::new(signers),
    };

    println!("{:?}", txin);
    descriptor.satisfy(&mut txin, signing_ctx).unwrap();
    println!("{:?}", txin);

    // println!("{:?}", signers.ids());
    println!("{:#?}", descriptor);
}
