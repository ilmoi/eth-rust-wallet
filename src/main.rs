use std::path::Path;
use std::str::FromStr;

use bip39::{Language, Mnemonic, MnemonicType, Seed};
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::{
    network::constants::Network,
    util::bip32::{DerivationPath, ExtendedPrivKey},
    PublicKey,
};
use eth_keystore::encrypt_key;
use hdpath::{Purpose, StandardHDPath};
use secp256k1::Secp256k1;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// How it works:
/// 1. generate a new mnemonic (tiny-bip39)
/// 2. mnemonic -> entropy -> keystore file (eth-keystore)
/// 3. mnemonic -> seed -> xpub -> pk, pubk -> eth addr (hdpath, bitcoin, secp25k1, sha3, eth_checksum)
fn main() {
    // ----------------------------------------------------------------------------- 1 mnemonic
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    println!("Mnemonic: {}", mnemonic);

    // ----------------------------------------------------------------------------- 2 keystore
    // save it as a keystore file
    // my understanding is that you save the entropy, not the seed into keystore - https://support.mycrypto.com/general-knowledge/ethereum-blockchain/difference-between-wallet-types
    let entropy = mnemonic.entropy();
    println!("Entropy: {:?}", entropy); //128 bits for 12 words, 256 bits for 24 words

    let mut rng = rand::thread_rng();
    let dir = Path::new("./keys");
    let uuid = encrypt_key(&dir, &mut rng, entropy, "password_to_keystore").unwrap();
    println!("File uuid: {}", uuid);

    // ----------------------------------------------------------------------------- 3 derived addr
    // get the HD wallet seed
    let seed = Seed::new(&mnemonic, ""); //128 hex chars = 512 bits
    let seed_bytes: &[u8] = seed.as_bytes();
    println!("Seed: {:X}", seed);
    println!("Seed as bytes: {:?}", seed_bytes);

    for i in (0..10) {
        let hd_path = StandardHDPath::new(Purpose::Pubkey, 60, 0, 0, i);
        let (_pk, pubk) = get_extended_keypair(&seed_bytes, &hd_path);
        let _eth_addr = extended_pubk_to_addr(&pubk);
    }

    // √ verify against https://iancoleman.io/bip39/#english
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EthAddr(String);

impl EthAddr {
    pub fn new(addr: &str) -> Self {
        let mut proper_addr = addr.to_owned();
        //check for 0x prefix
        if !addr.starts_with("0x") {
            proper_addr = format!("0x{}", addr);
        }
        //check that passed str is a hex string
        hex::decode(&proper_addr[2..])
            .map_err(|e| {
                println!("String passed into EthAddr is not hex.");
                e
            })
            .unwrap();
        //check length
        if proper_addr.len() != 42 {
            panic!(
                "String passed into EthAddr is {} hex chars long instead of 42.",
                proper_addr.len()
            );
        }
        //checksum and return
        let checksummed_addr = eth_checksum::checksum(&proper_addr);
        println!("New eth addr: {}", checksummed_addr);
        Self(checksummed_addr)
    }
    pub fn get(&self) -> &str {
        &self.0
    }
}

fn get_extended_keypair(
    seed: &[u8],
    hd_path: &StandardHDPath,
) -> (ExtendedPrivKey, ExtendedPubKey) {
    let secp = Secp256k1::new();
    let pk = ExtendedPrivKey::new_master(Network::Bitcoin, seed)
        // we convert HD Path to bitcoin lib format (DerivationPath)
        .and_then(|k| k.derive_priv(&secp, &DerivationPath::from(hd_path)))
        .unwrap();
    let pubk = ExtendedPubKey::from_private(&secp, &pk);

    println!("HD path: {}", hd_path);
    // println!(
    //     "xprv: {}, pk: {}, chain_code: {}",
    //     pk, pk.private_key, pk.chain_code
    // );
    // println!(
    //     "xpub: {}, pubk: {}, chain_code: {}",
    //     pubk, pubk.public_key, pubk.chain_code
    // );

    (pk, pubk)
}

fn extended_pubk_to_addr(pubk: &ExtendedPubKey) -> EthAddr {
    //massage into the right format
    let pubk_str = pubk.public_key.to_string();
    let pubk_secp = secp256k1::PublicKey::from_str(&pubk_str).unwrap();
    //format as uncompressed key, remove "04" in the beginning
    let pubk_uncomp = &PublicKey::new_uncompressed(pubk_secp).to_string()[2..];
    //decode from hex and pass to keccak for hashing
    let pubk_bytes = hex::decode(pubk_uncomp).unwrap();
    let addr = &keccak_hash(&pubk_bytes);
    //keep last 20 bytes of the result
    let addr = &addr[(addr.len() - 40)..];
    //massage into domain unit
    EthAddr::new(addr)
}

fn keccak_hash<T>(data: &T) -> String
where
    T: ?Sized + Serialize + AsRef<[u8]>,
{
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let hex_r = hex::encode(result);
    hex_r
}
