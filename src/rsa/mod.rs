// https://tools.ietf.org/html/rfc8017#section-3.2

// This is a fake module until I get key pair generation down.
// In the meantime, have this hard coded keypair from
// https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Example

// Implementation is over the, relatively, small u64 type
// until fast arithmentic operations over larger types
// are implemented.

use num_bigint::BigUint;
use std::mem::transmute;

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

fn RSAEP(pubkey: PublicKey, m: &BigUint) -> BigUint {
    m.modpow(&pubkey.e, &pubkey.n)
}

fn RSADP(privkey: PrivateKey, c: &BigUint) -> BigUint {
    c.modpow(&privkey.d, &privkey.n)
}

// @TODO enticingly easy, but dragons.
fn I2OSP(x: u32, _xLen: u32) -> [u8; 4] {
    unsafe { transmute(x) }
}

// @TODO enticingly easy, but dragons.
fn OS2IP(X: [u8; 4]) -> u32 {
    unsafe { transmute(X) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt() {
        let want = BigUint::new(vec![42]);
        let (pubkey, privkey) = new_key_pair();
        let ciphertext = RSAEP(pubkey, &want);
        let got = RSADP(privkey, &ciphertext);
        assert_eq!(want, got);
    }
}
