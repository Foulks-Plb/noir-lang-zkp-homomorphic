use dep::std::ec::tecurve::affine::Curve as AffineCurve;
use dep::std::ec::tecurve::affine::Point as Gaffine;
use dep::std::collections::vec::Vec;
use dep::std::hash::poseidon2;
use dep::noir_elgamal;  

fn main(
 privateKey: Field, randomness1: Field, randomness2: Field, netAmount: u64, clearBalanceOldFrom: u64,
 publicKeyFrom: pub Gaffine, publicKeyTo: pub Gaffine, 
 encryptedBalanceOldFrom_1: pub Gaffine, encryptedBalanceOldFrom_2: pub Gaffine, encryptedBalanceOldTo_1: pub Gaffine, encryptedBalanceOldTo_2: pub Gaffine,
 encryptedBalanceNewFrom_1: pub Gaffine, encryptedBalanceNewFrom_2: pub Gaffine, encryptedBalanceNewTo_1: pub Gaffine, encryptedBalanceNewTo_2: pub Gaffine,
 hash: pub Field, amount: Field, secretShare: Gaffine
 ) { 
    let computed_public_key =  noir_elgamal::priv_to_pub_key(privateKey);
    assert((publicKeyFrom.x == computed_public_key.x) & (publicKeyFrom.y == computed_public_key.y), "Public key and Private key not valid");
    assert(netAmount<=clearBalanceOldFrom, "netAmount superior to balance");
    assert(netAmount>=1, "netAmount not superior to 0");

    let hashBuild = poseidon2::Poseidon2::hash([netAmount as Field, amount, secretShare.x, secretShare.y], 4);
    assert(hash == hashBuild, "Hash not valid");

    let bjj_affine: AffineCurve = AffineCurve::new(bjj_a, bjj_d, Gaffine::new(bjj_generator_x, bjj_generator_y));
    let base_pt: Gaffine = Gaffine::new(bjj_basept_x, bjj_basept_y);
    let embedded_balance_old_me_clear = bjj_affine.mul(clearBalanceOldFrom as Field, base_pt);
    let decoded_value = noir_elgamal::exp_elgamal_decrypt(privateKey, (encryptedBalanceOldFrom_1,encryptedBalanceOldFrom_2));
    assert((decoded_value.x == embedded_balance_old_me_clear.x) & (decoded_value.y == embedded_balance_old_me_clear.y), "Decrypted old from balance not valid");

    let balance_new_me_encrypted_computed = noir_elgamal::exp_elgamal_encrypt(publicKeyFrom, clearBalanceOldFrom - netAmount, randomness1);
    assert((balance_new_me_encrypted_computed.0.x==encryptedBalanceNewFrom_1.x) & (balance_new_me_encrypted_computed.0.y==encryptedBalanceNewFrom_1.y) & (balance_new_me_encrypted_computed.1.x==encryptedBalanceNewFrom_2.x) & (balance_new_me_encrypted_computed.1.y==encryptedBalanceNewFrom_2.y), "Encrypted new from balance not valid");
    
    let value_encrypted_to = noir_elgamal::exp_elgamal_encrypt(publicKeyTo, netAmount, randomness2);
    let mut balance_new_to_encrypted_computed: (Gaffine,Gaffine) = (Gaffine::new(0,0),Gaffine::new(0,0));
    if (encryptedBalanceOldTo_1.x == 0) & (encryptedBalanceOldTo_1.y == 0) {
        balance_new_to_encrypted_computed = value_encrypted_to;
    } else {
        balance_new_to_encrypted_computed = (bjj_affine.add(encryptedBalanceOldTo_1, value_encrypted_to.0),bjj_affine.add(encryptedBalanceOldTo_2, value_encrypted_to.1));
    }
    assert((balance_new_to_encrypted_computed.0.x==encryptedBalanceNewTo_1.x) & (balance_new_to_encrypted_computed.0.y==encryptedBalanceNewTo_1.y) & (balance_new_to_encrypted_computed.1.x==encryptedBalanceNewTo_2.x) & (balance_new_to_encrypted_computed.1.y==encryptedBalanceNewTo_2.y), "Encrypted new to balance not valid");
}

// #[test]
// fn test_main() {
// }