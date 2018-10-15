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

const hLen: usize = 256;

type Signature = BigUint;

struct PublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

#[derive(Debug)]
struct PrivateKey {
    pub n: BigUint,
    pub d: BigUint,
}

fn new_key_pair() -> (PublicKey, PrivateKey) {
    // @TODO https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation
    (
        PublicKey {
            n: BigUint::new(vec![3233]),
            e: BigUint::new(vec![17]),
        },
        PrivateKey {
            n: BigUint::new(vec![3233]),
            d: BigUint::new(vec![413]),
        },
    )
}

fn RSAEP(pubkey: &PublicKey, m: &BigUint) -> BigUint {
    m.modpow(&pubkey.e, &pubkey.n)
}

fn RSADP(privkey: &PrivateKey, c: &BigUint) -> BigUint {
    c.modpow(&privkey.d, &privkey.n)
}

#[cfg(target_endian = "big")]
fn I2OSP(x: BigUint) -> Vec<u8> {
    x.to_bytes_be()
}

#[cfg(target_endian = "little")]
fn I2OSP(x: BigUint) -> Vec<u8> {
    x.to_bytes_le()
}

#[cfg(target_endian = "big")]
fn OS2IP(X: Vec<u8>) -> BigUint {
    BigUint::from_bytes_be(&X)
}

#[cfg(target_endian = "little")]
fn OS2IP(X: Vec<u8>) -> BigUint {
    BigUint::from_bytes_le(&X)
}

fn RSASP1(K: &PrivateKey, m: &BigUint) -> Signature {
    // @TODO step one validation
    m.modpow(&K.d, &K.n)
}

fn RSAVP1(X: &PublicKey, s: &Signature) -> BigUint {
    s.modpow(&X.e, &X.n)
}

fn RSAES_OAEP_ENCRYPT(pubkey: &PublicKey, M: Vec<u8>, L: &Vec<u8>) -> Vec<u8> {
    // @TODO input validation step
    // k - mLen - 2hLen - 2 zero octets
    // 2. EME-OAEP encoding
    let EM = EME_OAEP_ENCODE(pubkey, M, L);
    let m = OS2IP(EM);
    let c = RSAEP(pubkey, &m);
    let C = I2OSP(c);
    C
}

fn EME_OAEP_ENCODE(pubkey: &PublicKey, mut M: Vec<u8>, L: &Vec<u8>) -> Vec<u8> {
    // b. Generate a padding string PS consisting of...
    //      k - mLen - 2hLen - 2
    //    ...zero octets. The length of PS may be zero.
    // !!!!!!!!
    // May be wrong as bits() strips leading zeroes.
    let k = pubkey.n.bits();
    // !!!!!!!!
    let mut PS = vec![0; k - M.len() - (2 * hLen) - 2];
    // c. Concatenate lHash, PS, a single octet with hexadecimal
    //           value 0x01, and the message M to form a data block DB of
    //           length k - hLen - 1 octets as
    //     DB = lHash || PS || 0x01 || M.
    let mut hasher = Sha256::new();
    hasher.input(L);
    let mut lHash = Vec::from(hasher.result().iter().as_slice());

    let mut DB = Vec::with_capacity(lHash.len() + PS.len() + 1 + M.len());
    DB.append(&mut lHash);
    DB.append(&mut PS);
    DB.push(0x01);
    DB.append(&mut M);
    // d. Generate a random octet string seed of length hLen.
    let mut rng = thread_rng();
    let seed = (0..hLen).map(|_| rng.next_u32() as u8).collect();
    // e. Let dbMask = MGF(seed, k - hLen - 1).
    let dbMask = MGF(&seed, k - hLen - 1);
    // f. Let maskedDB = DB \xor dbMask.
    let mut maskedDB: Vec<u8> = DB
        .iter()
        .enumerate()
        .map(|(index, value)| value ^ dbMask[index])
        .collect();
    // g. Let seedMask = MGF(maskedDB, hLen).
    let seedMask = MGF(&maskedDB, hLen);
    // h. Let maskedSeed = seed \xor seedMask.
    let mut maskedSeed: Vec<u8> = seed
        .iter()
        .enumerate()
        .map(|(index, value)| value ^ seedMask[index])
        .collect();
    // i. Concatenate a single octet with hexadecimal value 0x00,
    //           maskedSeed, and maskedDB to form an encoded message EM of
    //           length k octets as
    //     EM = 0x00 || maskedSeed || maskedDB.
    let mut EM: Vec<u8> = Vec::with_capacity(k);
    EM.push(0x00);
    EM.append(&mut maskedSeed);
    EM.append(&mut maskedDB);
    // May or may not be necessary, just...ya know...asserting.
    assert_eq!(EM.len(), k);
    EM
}

// https://tools.ietf.org/html/rfc8017#appendix-B.2.1
fn MGF(mgfSeed: &Vec<u8>, maskLen: usize) -> Vec<u8> {
    let mut T: Vec<u8> = vec![];
    for counter in 0..((maskLen as f32 / hLen as f32).ceil() as usize) - 1 {
        let mut hasher = Sha256::new();
        let C = I2OSP(BigUint::from(counter));
        hasher.input(&mgfSeed);
        hasher.input(C);
        T.append(&mut Vec::from(hasher.result().iter().as_slice()));
    }
    T[0..maskLen].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt() {
        let want = BigUint::new(vec![42]);
        let (pubkey, privkey) = new_key_pair();
        let ciphertext = RSAEP(&pubkey, &want);
        let got = RSADP(&privkey, &ciphertext);
        assert_eq!(want, got);
    }

    #[test]
    fn verification() {
        let want = BigUint::new(vec![84]);
        let (pubkey, privkey) = new_key_pair();
        let signature = RSASP1(&privkey, &want);
        let got = RSAVP1(&pubkey, &signature);
        assert_eq!(want, got);
    }
}
