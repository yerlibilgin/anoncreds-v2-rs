use super::{PokSignatureProof, PublicKey};
use crate::knox::short_group_sig_core::short_group_traits::ProofOfSignatureKnowledge;
use blsful::inner_types::{ff::Field, Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde_json::json;

/// This struct represents an Verifier of signatures.
/// Provided are methods for generating a context to ask for revealed messages
/// and the prover keep all others hidden.
pub struct Verifier;

impl Verifier {
    /// Create a nonce used for the proof request context
    pub fn generate_proof_nonce(rng: impl RngCore + CryptoRng) -> Scalar {
        Scalar::random(rng)
    }

    /// Check a signature proof of knowledge and selective disclosure proof
    pub fn verify_signature_pok(
        revealed_msgs: &[(usize, Scalar)],
        public_key: &PublicKey,
        proof: PokSignatureProof,
        nonce: Scalar,
        challenge: Scalar,
    ) -> bool {
        let mut transcript = Transcript::new(b"signature proof of knowledge");
        proof.add_proof_contribution(public_key, revealed_msgs, challenge, &mut transcript);
        transcript.append_message(b"nonce", nonce.to_be_bytes().as_ref());
        let mut res = [0u8; 64];
        transcript.challenge_bytes(b"signature proof of knowledge", &mut res);
        let v_challenge = Scalar::from_bytes_wide(&res);

        proof.verify(revealed_msgs, public_key).is_ok() && challenge == v_challenge
    }
}

#[test]
fn pok_sig_proof_works() {
    use super::{Issuer, PokSignature};
    use crate::knox::short_group_sig_core::{
        short_group_traits::ProofOfSignatureKnowledgeContribution, *,
    };

    let mut rng = rand_core::OsRng;

    let (pk, sk) = Issuer::new_keys(5, &mut rng).unwrap();
    let messages = [
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    ];

    let res = Issuer::sign(&sk, &messages);
    assert!(res.is_ok());

    let signature = res.unwrap();

    let proof_messages = [
        ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(messages[0])),
        ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(messages[1])),
        ProofMessage::Hidden(HiddenMessage::ExternalBlinding(messages[2], Scalar::from(5u64))),
        ProofMessage::Revealed(messages[3]),
        ProofMessage::Revealed(messages[4]),
    ];

    let res = PokSignature::commit(signature, &pk, &proof_messages, &mut rng);
    assert!(res.is_ok());

    let pok_sig = res.unwrap();
    let nonce = Verifier::generate_proof_nonce(&mut rng);
    let mut transcript = Transcript::new(b"signature proof of knowledge");
    pok_sig.add_proof_contribution(&mut transcript);
    transcript.append_message(b"nonce", nonce.to_be_bytes().as_ref());
    let mut tmp = [0u8; 64];
    transcript.challenge_bytes(b"signature proof of knowledge", &mut tmp);
    let challenge = Scalar::from_bytes_wide(&tmp);
    let res = pok_sig.generate_proof(challenge);
    assert!(res.is_ok());

    let rvl_msgs = &[(3, messages[3]), (4, messages[4])];
    let proof = res.unwrap();
    assert!(proof.verify(rvl_msgs, &pk).is_ok());

    let mut transcript = Transcript::new(b"signature proof of knowledge");
    proof.add_proof_contribution(&pk, rvl_msgs, challenge, &mut transcript);
    transcript.append_message(b"nonce", nonce.to_be_bytes().as_ref());
    transcript.challenge_bytes(b"signature proof of knowledge", &mut tmp);
    let challenge2 = Scalar::from_bytes_wide(&tmp);
    assert_eq!(challenge, challenge2);

    println!("Proof: {:}", serde_json::to_string_pretty(&proof).unwrap());

    assert!(Verifier::verify_signature_pok(
        &[(3, messages[3]), (4, messages[4])][..],
        &pk,
        proof,
        nonce,
        challenge
    ));
}
