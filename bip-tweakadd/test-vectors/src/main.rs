use secp256k1::{constants::CURVE_ORDER, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Implements OP_TWEAKADD semantics.
/// Returns None if invalid scalar, invalid x, or infinity.
fn tweak_add_xonly(pubkey32: [u8; 32], h32: [u8; 32]) -> Option<[u8; 32]> {
    let secp = Secp256k1::new();

    // Reject if t >= n
    let scalar = secp256k1::Scalar::from_be_bytes(h32).ok()?;
    // Lift pubkey from x-only
    let xpk = XOnlyPublicKey::from_slice(&pubkey32).ok()?;
    let (xonly, _) = xpk.add_tweak(&secp, &scalar).ok()?;
    Some(xonly.serialize())
}

fn case(name: &str, pubkey_hex: &str, t_hex: &str, check_res: Option<&str>) {
    let pk_bytes = hex::decode(pubkey_hex).unwrap();
    let t_bytes = hex::decode(t_hex).unwrap();
    let mut pk32 = [0u8; 32];
    pk32.copy_from_slice(&pk_bytes);
    let mut t32 = [0u8; 32];
    t32.copy_from_slice(&t_bytes);
    match tweak_add_xonly(pk32, t32) {
        Some(out) => {
            let out_hex = hex32(&out);
            if let Some(check) = check_res {
                assert_eq!(out_hex, check);
            }

            let script = format!("<{pubkey_hex}> <{t_hex}> OP_TWEAKADD <{out_hex}> OP_EQUAL");

            println!("{name}\n```\n  pubkey32    =  {pubkey_hex}\n  h32         =  {t_hex}\n  expect      =  {out_hex}\n\n  script      =  {script}\n```")
        }
        None => {
            let script = format!("<{pubkey_hex}> <{t_hex}> OP_TWEAKADD OP_DROP OP_1");
            println!("{name}\n```\n  pubkey32    =  {pubkey_hex}\n  h32         =  {t_hex}\n  expect      =  fail\n  script      =  {script}\n```")
        }
    }
}

/// Helper: compute x-only for scalar*k*G.
fn xonly_of_scalar(k: u8) -> String {
    let secp = Secp256k1::new();
    let mut buf = [0u8; 32];
    buf[31] = k;
    let sk = SecretKey::from_slice(&buf).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let (xonly, _) = pk.x_only_public_key();
    hex32(&xonly.serialize())
}

fn hash_scalar(k: u8) -> [u8; 32] {
    bitcoin_hashes::Sha256::hash(&[k]).to_byte_array()
}
/// Helper: compute x-only for scalar*k*G.
fn xonly_of_scalar_hash(k: [u8; 32]) -> String {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&k).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let (xonly, _) = pk.x_only_public_key();
    hex32(&xonly.serialize())
}

fn main() {
    println!("Curve order n = {}", hex::encode(CURVE_ORDER));
    println!();

    let x_g = xonly_of_scalar(1);
    let x_2g = xonly_of_scalar(2);
    let x_3g = xonly_of_scalar(3);
    let x_5g = xonly_of_scalar(5);
    let x_6g = xonly_of_scalar(6);
    let x_7g = xonly_of_scalar(7);
    let x_16g = xonly_of_scalar(16);

    let h1 = hash_scalar(1);
    let h2 = hash_scalar(2);
    let h7 = hash_scalar(7);
    let x_h1g = xonly_of_scalar_hash(h1);
    let x_h2g = xonly_of_scalar_hash(h2);
    let x_h7g = xonly_of_scalar_hash(h7);

    println!("\n### Passing cases\n");
    case(
        "1) Identity tweak (t = 0)",
        &x_g,
        "0000000000000000000000000000000000000000000000000000000000000000",
        Some(&x_g),
    );
    case(
        "2) Increment by 1",
        &x_g,
        "0000000000000000000000000000000000000000000000000000000000000001",
        Some(&x_2g),
    );
    case(
        "3) Increment by 2",
        &x_g,
        "0000000000000000000000000000000000000000000000000000000000000002",
        Some(&x_3g),
    );
    case(
        "4) Increment by 5",
        &x_g,
        "0000000000000000000000000000000000000000000000000000000000000005",
        Some(&x_6g),
    );
    case(
        "5) Input x(2G), t = 3",
        &x_2g,
        "0000000000000000000000000000000000000000000000000000000000000003",
        Some(&x_5g),
    );
    case(
        "6) Input x(7G), t = 9",
        &x_7g,
        "0000000000000000000000000000000000000000000000000000000000000009",
        Some(&x_16g),
    );

    case(
        "7) Input x(h(1) G), t = 1",
        &x_h1g,
        "0000000000000000000000000000000000000000000000000000000000000001",
        None,
    );
    case(
        "8) Input x(h(2) G), t = 1",
        &x_h2g,
        "0000000000000000000000000000000000000000000000000000000000000001",
        None,
    );
    case(
        "9) Input x(h(7) G), t = 1",
        &x_h7g,
        "0000000000000000000000000000000000000000000000000000000000000001",
        None,
    );

    case("10) Input x(G), t = 1", &x_g, &hex32(&h1), None);
    case("11) Input x(G), t = h(2)", &x_g, &hex32(&h2), None);
    case(
        "12) Input x(G), t = h(7) (Note: differs from 9)",
        &x_g,
        &hex32(&h7),
        None,
    );

    println!("\n### Failing cases\n");
    case(
        "A) Scalar out of range (t = n)",
        &x_g,
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        None,
    );
    case(
        "B) Invalid x (x = 0), t = 1",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001",
        None,
    );
    case(
        "C) Infinity result (x(G), t = n-1)",
        &x_g,
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        None,
    );
}
