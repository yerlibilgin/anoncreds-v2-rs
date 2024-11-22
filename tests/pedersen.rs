#[cfg(test)]
mod tests {
  use std::ops::Neg;
  use blstrs_plus::{G1Projective, G2Projective, Scalar};
  use blstrs_plus::elliptic_curve::Field;
  use blstrs_plus::group::{Curve, Group};
  use blstrs_plus::group::prime::PrimeCurveAffine;
  use rand::Rng;


  #[derive(Debug)]
  struct PedersenCommitment<C>
  where
    C: Curve + Group + std::ops::Mul<Scalar, Output=C>,  // Ensure C can be multiplied with Scalar
  {
    commitment: C,
    blinding_factor: Scalar,
  }
  // Updated function to return the new polymorphic PedersenCommitment struct
  fn generate_pedersen_commitment<C>(message: Scalar) -> PedersenCommitment<C>
  where
    C: Curve + Group + std::ops::Mul<Scalar, Output=C>,  // C must implement Curve, Group, and Mul traits
  {
    let mut rng = rand::thread_rng();

    // Generators for the Pedersen commitment (either G1 or G2)
    let g = C::generator(); // Using the generator from the group
    let h = C::random(&mut rng); // Random generator for blinding factor

    // Choose a random blinding factor
    let blinding_factor = Scalar::random(&mut rng);

    // Calculate the Pedersen commitment: C = g^m * h^r
    let commitment = g * message + h * blinding_factor;

    PedersenCommitment {
      commitment,
      blinding_factor,
    }
  }

  #[test]
  fn test_pedersen_commitment_g1() {
    let mut rng = rand::thread_rng();


    // Example message as a scalar
    let message = Scalar::from(rng.gen::<u64>());

    // Generate the Pedersen commitment in G1
    let pedersen_commitment = generate_pedersen_commitment::<G1Projective>(message);

    println!("Pedersen Commitment (G1): {:?}", pedersen_commitment.commitment);
    println!("Blinding Factor: {:?}", pedersen_commitment.blinding_factor);
  }

  #[test]
  fn test_pedersen_commitment_g2() {
    let mut rng = rand::thread_rng();

    // Example message as a scalar
    let message = Scalar::from(rng.gen::<u64>());

    // Generate the Pedersen commitment in G2
    let pedersen_commitment = generate_pedersen_commitment::<G2Projective>(message);

    println!("Pedersen Commitment (G2): {:?}", pedersen_commitment.commitment);
    println!("Blinding Factor: {:?}", pedersen_commitment.blinding_factor);
  }

  #[test]
  fn test_pedersen_commitment_g3() {
    let k = Scalar::from(4u128); //Scalar::random(&mut rng);
    let l = Scalar::from(5u128); //Scalar::random(&mut rng);
    let m = Scalar::from(7u128); //Scalar::random(&mut rng);
    let n = k + m * l;

    println!("K: {:?}", k);
    println!("L: {:?}", l);
    println!("M: {:?}", m);
    println!("n: {:?}", n);

    let g = G1Projective::generator();

    // G ^ (k + l * m) = G ^ n ?
    let t1 = g * k + g * (l * m);
    println!("        t1: {:?}", t1);
    println!("        t1: {:?}", t1.to_affine());
    println!("        t1: {:?}", t1.to_affine().to_curve());

    let t2 = g * n;
    println!("        t2: {:?}", t2);
    println!("        t2: {:?}", t2.to_affine().to_curve());
    println!("        t2: {:?}", t2.to_affine().to_curve());


    let affine_point = G1Projective::generator().to_affine();  // an affine point
    let projective_point = affine_point.to_curve();  // convert to projective coordinates


    let affine_point = G1Projective::generator().to_affine(); // an affine point
    let compressed = affine_point.to_compressed(); // convert to compressed form

    let hex_string = hex::encode(compressed);
    println!("Compressed point: {:}",  hex_string);
    let affine_point = G1Projective::generator().neg().to_affine(); // an affine point
    let compressed = affine_point.to_compressed(); // convert to compressed form

    let hex_string = hex::encode(compressed);
    println!("Compressed point: {:}",  hex_string);

    assert_eq!(t1, t2);


    let t3 = (g * l ) * m;
    let t4 = g * (l * m);

    assert_eq!(t3, t4);

  }

  #[test]
  fn test_commit_verify() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();


    let g = G1Projective::generator();
    let h = G1Projective::random(&mut rng);

    struct ProverData {
      m: Scalar,
      r: Scalar,
      m_prime: Scalar,
      r_prime: Scalar,
    }

    let mut prover_data = ProverData {
      m: Default::default(),
      r: Default::default(),
      m_prime: Default::default(),
      r_prime: Default::default(),
    };

    let commitment = {
      //Step1 - Prover creates a commitment

      // Example message as a scalar
      let m = Scalar::random(&mut rng); //r
      let r = Scalar::random(&mut rng); //r

      //C = g^v * h^r
      let commitment = g * m + h * r;

      println!("Private Message: {:?}", m);
      println!("Blinding Factor: {:?}", r);
      println!("G: {:?}", g);
      println!("H: {:?}", h);

      println!("Pedersen Commitment (G1): {:?}", &commitment);

      prover_data.m = m;
      prover_data.r = r;
      commitment
    };


    println!("-------------------");
    let proof = {
      //Step2 - Prover calculates a Proof (T)

      let m_prime = Scalar::random(&mut rng);
      let r_prime = Scalar::random(&mut rng);
      let t = g * m_prime + h * r_prime;
      println!("m_prime: {:?}", m_prime);
      println!("r_prime: {:?}", r_prime);
      println!("T: {:?}", t);

      prover_data.m_prime = m_prime;
      prover_data.r_prime = r_prime;

      t
    };

    println!("-------------------");
    //verifier issues a random challenge
    let challenge = Scalar::random(&mut rng);
    println!("Challege: {:?}", challenge);

    println!("-------------------");
    let (s_m, s_r) = {
      //prover computes responses
      //s_v = k_v + c * v
      let s_m = prover_data.m_prime + challenge * prover_data.m;
      //s_r = k_r + c * r
      let s_r = prover_data.r_prime + challenge * prover_data.r;
      println!("s_m: {:?}", s_m);
      println!("s_r: {:?}", s_r);

      (s_m, s_r)
    };

    //Verify
    let t_prime = g * s_m + h * s_r;
    println!("t_prime: {:?}", t_prime.to_affine().to_curve());

    let t_prime_2 = proof + commitment * challenge;

    println!("t_prime_2: {:?}", t_prime_2.to_affine());

    println!("Equal? : {} ", t_prime == t_prime_2);

    Ok(())
  }
}
