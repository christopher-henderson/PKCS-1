// https://tools.ietf.org/html/rfc8017#section-3.2

// This is a fake module until I get key pair generation down.
// In the meantime, have this hard coded keypair from
// https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Example

// Implementation is over the, relatively, small u64 type
// until fast arithmentic operations over larger types
// are implemented.

use num_bigint::BigUint;
use rand::thread_rng;
use rand_core::RngCore;

use sha2::{Digest, Sha256};

const H_LEN: usize = 256;

type Signature = BigUint;

#[derive(Debug)]
pub struct PublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

#[derive(Debug)]
pub struct PrivateKey {
    pub n: BigUint,
    pub d: BigUint,
}

pub fn new_key_pair() -> (PublicKey, PrivateKey) {
    // @TODO https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation
    (
        PublicKey {
            n: BigUint::from(3233 as u32),
            e: BigUint::from(17 as u32),
        },
        PrivateKey {
            n: BigUint::from(3233 as u32),
            d: BigUint::from(413 as u32),
        },
    )
}

pub fn rsaes_oaep_encrypt(pubkey: &PublicKey, m: Vec<u8>, l: &Vec<u8>) -> Vec<u8> {
    // @TODO input validation step
    // k - mLen - 2H_LEN - 2 zero octets
    // 2. EME-OAEP encoding
    let em = eme_oaep_encode(pubkey, m, l);
    let m = os2ip(em);
    let c = rsaep(pubkey, &m);
    i2osp(c)
}

fn rsaep(pubkey: &PublicKey, m: &BigUint) -> BigUint {
    m.modpow(&pubkey.e, &pubkey.n)
}

fn rsadp(privkey: &PrivateKey, c: &BigUint) -> BigUint {
    c.modpow(&privkey.d, &privkey.n)
}

#[cfg(target_endian = "big")]
fn i2osp(x: BigUint) -> Vec<u8> {
    x.to_bytes_be()
}

#[cfg(target_endian = "little")]
fn i2osp(x: BigUint) -> Vec<u8> {
    x.to_bytes_le()
}

#[cfg(target_endian = "big")]
fn os2ip(x: Vec<u8>) -> BigUint {
    BigUint::from_bytes_be(&X)
}

#[cfg(target_endian = "little")]
fn os2ip(x: Vec<u8>) -> BigUint {
    BigUint::from_bytes_le(&x)
}

fn rsasp1(k: &PrivateKey, m: &BigUint) -> Signature {
    // @TODO step one validation
    m.modpow(&k.d, &k.n)
}

fn rsavp1(x: &PublicKey, s: &Signature) -> BigUint {
    s.modpow(&x.e, &x.n)
}

fn eme_oaep_encode(pubkey: &PublicKey, mut m: Vec<u8>, l: &Vec<u8>) -> Vec<u8> {
    // b. Generate a padding string PS consisting of...
    //      k - mLen - 2H_LEN - 2
    //    ...zero octets. The length of PS may be zero.
    // !!!!!!!!
    // May be wrong as bits() strips leading zeroes.
    let k = pubkey.n.bits();
    // !!!!!!!!
    let mut ps = vec![0; k - m.len() - (2 * H_LEN) - 2];
    // c. Concatenate lHash, PS, a single octet with hexadecimal
    //           value 0x01, and the message M to form a data block DB of
    //           length k - H_LEN - 1 octets as
    //     DB = lHash || PS || 0x01 || M.
    let mut hasher = Sha256::new();
    hasher.input(l);
    let mut l_hash = Vec::from(hasher.result().iter().as_slice());

    let mut db = Vec::with_capacity(l_hash.len() + ps.len() + 1 + m.len());
    db.append(&mut l_hash);
    db.append(&mut ps);
    db.push(0x01);
    db.append(&mut m);
    // d. Generate a random octet string seed of length H_LEN.
    let mut rng = thread_rng();
    let seed = (0..H_LEN).map(|_| rng.next_u32() as u8).collect();
    // e. Let dbMask = mgf(seed, k - H_LEN - 1).
    let db_mask = mgf(&seed, k - H_LEN - 1);
    // f. Let maskedDB = DB \xor dbMask.
    let mut masked_db: Vec<u8> = db
        .iter()
        .enumerate()
        .map(|(index, value)| value ^ db_mask[index])
        .collect();
    // g. Let seedMask = mgf(maskedDB, H_LEN).
    let seed_mask = mgf(&masked_db, H_LEN);
    // h. Let maskedSeed = seed \xor seedMask.
    let mut masked_seed: Vec<u8> = seed
        .iter()
        .enumerate()
        .map(|(index, value)| value ^ seed_mask[index])
        .collect();
    // i. Concatenate a single octet with hexadecimal value 0x00,
    //           maskedSeed, and maskedDB to form an encoded message EM of
    //           length k octets as
    //     EM = 0x00 || maskedSeed || maskedDB.
    let mut em: Vec<u8> = Vec::with_capacity(k);
    em.push(0x00);
    em.append(&mut masked_seed);
    em.append(&mut masked_db);
    // May or may not be necessary, just...ya know...asserting.
    assert_eq!(em.len(), k);
    em
}

// https://tools.ietf.org/html/rfc8017#appendix-B.2.1
fn mgf(mgf_seed: &Vec<u8>, mask_len: usize) -> Vec<u8> {
    let mut t: Vec<u8> = vec![];
    for counter in 0..((mask_len as f32 / H_LEN as f32).ceil() as usize) - 1 {
        let mut hasher = Sha256::new();
        let c = i2osp(BigUint::from(counter));
        hasher.input(&mgf_seed);
        hasher.input(c);
        t.append(&mut Vec::from(hasher.result().iter().as_slice()));
    }
    t[0..mask_len].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let want = BigUint::new(vec![42]);
        let (pubkey, privkey) = new_key_pair();
        let ciphertext = rsaep(&pubkey, &want);
        let got = rsadp(&privkey, &ciphertext);
        assert_eq!(want, got);
    }

    #[test]
    fn test_verification() {
        let want = BigUint::new(vec![84]);
        let (pubkey, privkey) = new_key_pair();
        let signature = rsasp1(&privkey, &want);
        let got = rsavp1(&pubkey, &signature);
        assert_eq!(want, got);
    }

    #[test]
    fn test_rsaes_oaep_encrypt() {
        let (pubkey, _) = new_key_pair();
        rsaes_oaep_encrypt(&pubkey, vec![], &vec![]);
        unimplemented!();
    }
}
