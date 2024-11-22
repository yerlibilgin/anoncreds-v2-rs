#[cfg(test)]
mod tests {
  use blstrs_plus::{pairing, G1Projective, G2Projective, Scalar};
  use blstrs_plus::elliptic_curve::Field;
  use blstrs_plus::group::{Curve, Group};
  use rand::Rng;
  use sha2::Digest;

  #[test]
  fn test_bls() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();

    let a = Scalar::from(rng.gen::<u64>());
    let b = Scalar::from(rng.gen::<u64>());

    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    let g1_a = g1 * a;
    let g2_b = g2 * b;

    let result = pairing(&g1_a.to_affine(), &g2_b.to_affine());
    println!("Pairing result: {:?}", result);

    let g1_a = g1 * a * b;
    let g2_b = g2;

    let result = pairing(&g1_a.to_affine(), &g2_b.to_affine());
    println!("Pairing result: {:?}", result);

    let g1_a = g1;
    let g2_b = g2 * a * b;

    let result = pairing(&g1_a.to_affine(), &g2_b.to_affine());
    println!("Pairing result: {:?}", result);

    let g1_a = g1;
    let g2_b = g2 * a;

    let result = pairing(&g1_a.to_affine(), &g2_b.to_affine());
    println!("Pairing result (must differ): {:?}", result);

    Ok(())
  }

  #[test]
  fn bbs_plus_sign_verify() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();

    let messages: Vec<Scalar> = vec![Scalar::from(rng.gen::<u64>()), Scalar::from(rng.gen::<u64>())];

    let (private_key, public_key) = generate_keys(messages.len() as u64);

    println!("Public key: {:?}", public_key);
    println!("Secret key: {:?}", private_key);
    let signature = sign_messages(&private_key, &public_key, &messages);

    println!("Signature: {:?}", signature);

    let is_valid = verify_signature(&signature, &messages, &public_key);
    println!("Signature valid: {}", is_valid);

    Ok(())
  }

  #[derive(Debug)]
  struct PublicKey {
    pub w: G2Projective,
  }

  #[derive(Debug)]
  struct BBSPlusSignature {
    a: G1Projective,
    h_0: G1Projective,
    h_vec: Vec<G1Projective>,
    e: Scalar,
    s: Scalar,
  }

  fn generate_keys(message_count: u64) -> (Scalar, PublicKey) {
    if message_count > 100 {
      panic!("message_count should be less than 100");
    }

    let mut rng = rand::thread_rng();
    let x = Scalar::random(&mut rng);

    let private_key = x;

    (private_key, PublicKey {
      w: G2Projective::generator() * x
    })
  }

  fn sign_messages(private_key: &Scalar, public_key: &PublicKey, messages: &[Scalar]) -> BBSPlusSignature {
    let mut rng = rand::thread_rng();

    let e = Scalar::random(&mut rng);
    let s = Scalar::random(&mut rng);

    let mut h_vec = Vec::new();
    let h_0 = G1Projective::generator() * Scalar::random(&mut rng);
    let mut b = G1Projective::generator() + h_0 * s;

    for message in messages {
      let h_i = G1Projective::random(&mut rng);
      let g = h_i * message;
      b += g;
      h_vec.push(h_i);
    }

    let e_plus_x = e + private_key;
    let inverse_e_plus_x = e_plus_x.invert().unwrap();

    let a = b * inverse_e_plus_x;

    BBSPlusSignature {
      a,
      h_0,
      h_vec,
      e,
      s,
    }
  }

  fn verify_signature(signature: &BBSPlusSignature, messages: &[Scalar], public_key: &PublicKey) -> bool {
    let wg_pow_e = public_key.w + G2Projective::generator() * signature.e;
    let lhs = pairing(&signature.a.to_affine(), &wg_pow_e.to_affine());

    println!("LHS: {:?}", lhs);

    let mut b = G1Projective::generator() + signature.h_0 * signature.s;

    for (i, message) in messages.iter().enumerate() {
      let g = signature.h_vec[i] * message;
      b += g;
    }

    let rhs = pairing(&b.to_affine(), &G2Projective::generator().to_affine());

    println!("RHS: {:?}", rhs);

    lhs == rhs
  }
}
