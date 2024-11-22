use blsful::inner_types::{Curve, Field}; // For necessary field and curve types
use blstrs_plus::{G1Projective, G2Projective, Scalar, pairing};
use blstrs_plus::group::Group;
use rand_core::OsRng; // For secure random number generation


pub struct PSSecretKey {
  x: Scalar,
  y: Vec<Scalar>,
}

pub struct PSPublicKey {
  g: G2Projective,
  x: G2Projective,
  y: Vec<G2Projective>,
}

pub struct PSSignature {
  sigma_1: G1Projective,
  sigma_2: G1Projective,
}

// Key generation: Generates a pair of keys (secret and public).
fn keygen(message_count: usize) -> (PSSecretKey, PSPublicKey) {
  // Secret key is a random scalar
  let x = Scalar::random(&mut OsRng);
  let mut y = Vec::new();

  let g_tilde = G2Projective::random(&mut OsRng);

  // Public key is a tuple of two elements in G1 and G2, respectively
  let x_tilde = g_tilde * x;
  let mut y_tilde = Vec::new();
  for _ in 0..message_count{
    let y_i = Scalar::random(&mut OsRng);
    y.push(y_i);
    y_tilde.push(g_tilde * y_i)
  }


  (
    PSSecretKey {
      x,
      y,
    },
    PSPublicKey {
      g: g_tilde,
      x: x_tilde,
      y: y_tilde,
    }
  )
}

// Sign a message: Sign a scalar message by computing g1 * m * sk
fn sign(sk: &PSSecretKey, message: &[Scalar]) -> PSSignature {
  // Signature is g1 * (sk * message)

  let t = Scalar::random(&mut OsRng);
  let h = G1Projective::random(&mut OsRng) * t;

  PSSignature {
    sigma_1: h.clone(),
    sigma_2: h * (sk.x + {
      let mut sum = Scalar::from(0u16);

      for (sk_i, m_i) in message.iter().zip(sk.y.iter()) {
        sum += sk_i * m_i;
      }

      sum
    }),
  }
}

// Verify a signature: Verifies if the signature is correct using the public key
fn verify(pk: &PSPublicKey, message: &[Scalar], signature: &PSSignature) -> bool {
  // e(σ1, ˜X · ˜Y^m) = e(h, ˜X · ˜Y^m) = e(h, ˜g)^(x+y·m) = e(h(x+y·m), ˜g) = e(σ2, ˜g).

  let sigma_1_affine = signature.sigma_1.to_affine();

  //todo: check sigma1 != 1
  let x_plus_y_to_m = (pk.x + {
    let mut sum = G2Projective::identity();

    for (m_i, pk_i) in message.iter().zip(pk.y.iter()) {
      sum += pk_i * m_i;
    }

    sum
  }).to_affine();
  let lhs = pairing(&sigma_1_affine, &x_plus_y_to_m);

  let sigma_2_affine = signature.sigma_2.to_affine();
  //e(g1 * sk * message, g2 * sk)
  let rhs = pairing(&sigma_2_affine, &pk.g.to_affine());

  println!("LHS: {:?}", lhs);
  println!("RHS: {:?}", rhs);
  lhs == rhs
}

#[cfg(test)]
mod tests {
  use super::*;
  use blstrs_plus::Scalar; // For defining a test message as a Scalar

  #[test]
  fn test_ps_multi_signature() {
    // 1. Key generation
    let (sk, pk) = keygen(5);

    // 2. Define a message (can be a hash of actual data, but here we use a scalar for simplicity)
    let message = [
      Scalar::random(&mut OsRng),
      Scalar::random(&mut OsRng),
      Scalar::random(&mut OsRng),
      Scalar::random(&mut OsRng),
      Scalar::random(&mut OsRng),
    ].to_vec();

    // 3. Sign the message
    let signature = sign(&sk, &message);

    // 4. Verify the signature
    let is_valid = verify(&pk, &message, &signature);

    // Assert that the signature is valid
    assert!(is_valid, "The signature should be valid for the given message and keys.");
  }
}
