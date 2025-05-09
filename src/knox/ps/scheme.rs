use super::{
    BlindSignature, BlindSignatureContext, PokSignature, PokSignatureProof, PublicKey, SecretKey,
    Signature,
};
use crate::error::Error;
use crate::knox::short_group_sig_core::short_group_traits::{
    BlindSignatureContext as _, ProofOfSignatureKnowledge, ProofOfSignatureKnowledgeContribution,
    ShortGroupSignatureScheme,
};
use crate::knox::short_group_sig_core::{ProofCommittedBuilder, ProofMessage};
use crate::CredxResult;
use blsful::inner_types::{G1Affine, G1Projective, Scalar};
use elliptic_curve::group::Curve;
use elliptic_curve::Field;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;

/// Pointcheval-Sanders scheme
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
pub struct PsScheme;

impl ShortGroupSignatureScheme for PsScheme {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;
    type BlindSignatureContext = BlindSignatureContext;
    type BlindSignature = BlindSignature;
    type ProofOfSignatureKnowledge = PokSignatureProof;
    type ProofOfSignatureKnowledgeContribution = PokSignature;

    fn new_keys(
        count: NonZeroUsize,
        rng: impl RngCore + CryptoRng,
    ) -> CredxResult<(Self::PublicKey, Self::SecretKey)> {
        SecretKey::random(count, rng)
            .map(|sk| {
                let pk = PublicKey::from(&sk);
                (pk, sk)
            })
            .ok_or(Error::General("invalid key generation"))
    }

    fn sign<M>(sk: &Self::SecretKey, msgs: M) -> CredxResult<Self::Signature>
    where
        M: AsRef<[Scalar]>,
    {
        Signature::new(sk, msgs)
    }

    fn blind_sign(
        ctx: &Self::BlindSignatureContext,
        sk: &Self::SecretKey,
        msgs: &[(usize, Scalar)],
        nonce: Scalar,
    ) -> CredxResult<Self::BlindSignature> {
        let tv1 = msgs.iter().map(|(i, _)| *i).collect::<Vec<usize>>();
        if ctx.verify(tv1.as_ref(), sk, nonce)? {
            BlindSignature::new(ctx.commitment, sk, msgs)
        } else {
            Err(Error::General("BlindSignatureError"))
        }
    }

    fn new_blind_signature_context(
        messages: &[(usize, Scalar)],
        public_key: &Self::PublicKey,
        nonce: Scalar,
        mut rng: impl RngCore + CryptoRng,
    ) -> CredxResult<(Self::BlindSignatureContext, Scalar)> {
        let mut points = Vec::new();
        let mut secrets = Vec::new();
        let mut committing = ProofCommittedBuilder::<G1Projective, G1Affine, Scalar>::new(
            G1Projective::sum_of_products,
        );

        for (i, m) in messages {
            if *i > public_key.y.len() {
                return Err(crate::error::Error::General("invalid blind signing"));
            }
            secrets.push(*m);
            points.push(public_key.y_blinds[*i]);
            committing.commit_random(public_key.y_blinds[*i], &mut rng);
        }

        let blinding = Scalar::random(&mut rng);
        secrets.push(blinding);
        points.push(G1Projective::GENERATOR);
        committing.commit_random(G1Projective::GENERATOR, &mut rng);

        let mut transcript = Transcript::new(b"new blind signature");
        transcript.append_message(b"public key", public_key.to_bytes().as_ref());
        let commitment = G1Projective::sum_of_products(points.as_ref(), secrets.as_ref());
        committing.add_challenge_contribution(b"random commitment", &mut transcript);
        transcript.append_message(
            b"blind commitment",
            commitment.to_affine().to_compressed().as_ref(),
        );
        transcript.append_message(b"nonce", nonce.to_be_bytes().as_ref());
        let mut res = [0u8; 64];
        transcript.challenge_bytes(b"blind signature context challenge", &mut res);
        let challenge = Scalar::from_bytes_wide(&res);
        let proofs = committing.generate_proof(challenge, secrets.as_slice())?;
        Ok((
            BlindSignatureContext {
                commitment,
                challenge,
                proofs,
            },
            blinding,
        ))
    }

    fn commit_signature_pok(
        signature: Self::Signature,
        public_key: &Self::PublicKey,
        messages: &[ProofMessage<Scalar>],
        rng: impl RngCore + CryptoRng,
    ) -> CredxResult<Self::ProofOfSignatureKnowledgeContribution> {
        PokSignature::commit(&signature, public_key, messages, rng)
    }

    fn verify_signature_pok(
        revealed_msgs: &[(usize, Scalar)],
        public_key: &Self::PublicKey,
        proof: &Self::ProofOfSignatureKnowledge,
        nonce: Scalar,
        challenge: Scalar,
    ) -> bool {
        let mut transcript = Transcript::new(b"signature proof of knowledge");
        proof.add_proof_contribution(public_key, revealed_msgs, challenge, &mut transcript);
        transcript.append_message(b"nonce", nonce.to_be_bytes().as_ref());
        let mut res = [0u8; 64];
        transcript.challenge_bytes(b"signature proof of knowledge", &mut res);
        let v_challenge = Scalar::from_bytes_wide(&res);

        proof.verify(public_key, revealed_msgs, challenge).is_ok() && challenge == v_challenge
    }
}
