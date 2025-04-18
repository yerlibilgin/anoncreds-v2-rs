use super::*;
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::presentation::verifiable_encryption_decryption::VerifiableEncryptionDecryptionBuilder;
use log::debug;

impl<S: ShortGroupSignatureScheme> Presentation<S> {
    /// Create a new presentation composed of 1 to many proofs
    pub fn create(
        credentials: &IndexMap<String, PresentationCredential<S>>,
        schema: &PresentationSchema<S>,
        nonce: &[u8],
    ) -> CredxResult<Self> {
        let rng = OsRng {};
        let mut transcript = Transcript::new(b"credx presentation");
        Self::add_curve_parameters_challenge_contribution(&mut transcript);
        transcript.append_message(b"nonce", nonce);
        schema.add_challenge_contribution(&mut transcript);

        let (signature_statements, predicate_statements) = Self::split_statements(schema);

        if signature_statements.len() > credentials.len() {
            return Err(Error::InvalidPresentationData(format!("the number of signature statements '{}' exceeds the number of supplied credentials '{}'", signature_statements.len(), credentials.len())));
        }

        for (k, _) in signature_statements.iter() {
            if !credentials.contains_key(*k) {
                return Err(Error::InvalidPresentationData(format!("not all signature statements have a corresponding credential. signature statement '{}' is missing a corresponding credential", k)));
            }
        }

        let messages = Self::get_message_types(
            credentials,
            &signature_statements,
            &predicate_statements,
            rng,
        )?;

        let mut builders = Vec::<PresentationBuilders<S>>::with_capacity(schema.statements.len());
        let mut disclosed_messages = IndexMap::new();

        for (id, sig_statement) in &signature_statements {
            if let Statements::Signature(ss) = sig_statement {
                let mut dm = IndexMap::new();
                let cred = if let PresentationCredential::Signature(cred) = &credentials[*id] {
                    cred
                } else {
                    continue;
                };
                for (index, claim) in cred.claims.iter().enumerate() {
                    if matches!(messages[id][index].1, ProofMessage::Revealed(_)) {
                        let label = ss.issuer.schema.claim_indices.get_index(index).unwrap();
                        dm.insert((*label).clone(), claim.clone());
                    }
                }
                Self::add_disclosed_messages_challenge_contribution(id, &dm, &mut transcript);
                let signature_messages = messages[*id].iter().map(|(_, m)| *m).collect::<Vec<_>>();
                let builder = SignatureBuilder::commit(
                    ss,
                    &cred.signature,
                    &signature_messages,
                    rng,
                    &mut transcript,
                )?;
                builders.push(builder.into());
                disclosed_messages.insert((*id).clone(), dm);
            }
        }

        let mut id_to_builder = IndexMap::new();
        let mut range_id = IndexSet::new();
        for (id, pred_statement) in &predicate_statements {
            match pred_statement {
                Statements::Equality(e) => {
                    let builder = EqualityBuilder::commit(e, credentials)?;
                    id_to_builder.insert(*id, builders.len());
                    builders.push(builder.into());
                }
                Statements::Revocation(a) => {
                    let (_, proof_message) = messages[&a.reference_id][a.claim];
                    if matches!(proof_message, ProofMessage::Revealed(_)) {
                        return Err(Error::InvalidClaimData(
                            "revealed claim cannot be used for set membership proofs",
                        ));
                    }
                    let credential = if let PresentationCredential::Signature(credential) =
                        &credentials[&a.reference_id]
                    {
                        credential
                    } else {
                        continue;
                    };
                    let builder = RevocationProofBuilder::commit(
                        a,
                        credential,
                        proof_message,
                        nonce,
                        &mut transcript,
                    )?;
                    id_to_builder.insert(*id, builders.len());
                    builders.push(builder.into());
                }
                Statements::Membership(m) => {
                    let (_, proof_message) = messages[&m.reference_id][m.claim];
                    if matches!(proof_message, ProofMessage::Revealed(_)) {
                        return Err(Error::InvalidClaimData(
                            "revealed claim cannot be used for set membership proofs",
                        ));
                    }
                    let credential = if let PresentationCredential::Membership(credential) =
                        &credentials[&m.id]
                    {
                        credential
                    } else {
                        continue;
                    };
                    let builder = MembershipProofBuilder::commit(
                        m,
                        credential,
                        proof_message,
                        nonce,
                        &mut transcript,
                    )?;
                    id_to_builder.insert(*id, builders.len());
                    builders.push(builder.into());
                }
                Statements::Commitment(c) => {
                    let (_, proof_message) = messages[&c.reference_id][c.claim];
                    if matches!(proof_message, ProofMessage::Revealed(_)) {
                        return Err(Error::InvalidClaimData(
                            "revealed claim cannot be used for commitment",
                        ));
                    }
                    let message = proof_message.get_message();
                    let blinder = proof_message.get_blinder(rng).unwrap();
                    let builder =
                        CommitmentBuilder::commit(c, message, blinder, rng, &mut transcript)?;
                    id_to_builder.insert(*id, builders.len());
                    builders.push(builder.into());
                }
                Statements::VerifiableEncryption(v) => {
                    let (_, proof_message) = messages[&v.reference_id][v.claim];
                    if matches!(proof_message, ProofMessage::Revealed(_)) {
                        return Err(Error::InvalidClaimData(
                            "revealed claim cannot be used for verifiable encryption",
                        ));
                    }
                    let message = proof_message.get_message();
                    let blinder = proof_message.get_blinder(rng).unwrap();
                    let builder = VerifiableEncryptionBuilder::commit(
                        v,
                        message,
                        blinder,
                        rng,
                        &mut transcript,
                    )?;
                    id_to_builder.insert(*id, builders.len());
                    builders.push(builder.into());
                }
                Statements::VerifiableEncryptionDecryption(v) => {
                    let (claim_data, proof_message) = &messages[&v.reference_id][v.claim];
                    if matches!(proof_message, ProofMessage::Revealed(_)) {
                        return Err(Error::InvalidClaimData(
                            "revealed claim cannot be used for verifiable encryption",
                        ));
                    }
                    let message = proof_message.get_message();
                    let blinder = proof_message.get_blinder(rng).unwrap();
                    let builder = VerifiableEncryptionDecryptionBuilder::commit(
                        v,
                        claim_data,
                        message,
                        blinder,
                        rng,
                        &mut transcript,
                    )?;
                    id_to_builder.insert(*id, builders.len());
                    builders.push(builder.into());
                }
                Statements::Range(_) => {
                    // handle after these since they depend on commitment builders
                    range_id.insert(*id);
                }
                Statements::Signature(_) => {}
            }
        }
        let mut range_builders = Vec::<PresentationBuilders<S>>::with_capacity(range_id.len());
        for id in range_id {
            if let Statements::Range(r) =
                predicate_statements
                    .get(id)
                    .ok_or(Error::InvalidPresentationData(format!(
                        "expected a predicate range proof statement with id '{}' but was not found",
                        id
                    )))?
            {
                let sig = if let PresentationCredential::Signature(sig) = credentials
                    .get(&r.signature_id)
                    .ok_or(Error::InvalidPresentationData(format!("range proof statement with id '{}' references a signature statement with id '{}' but no signature statement has that id.", id, r.signature_id)))?
                {
                    sig
                } else {
                    continue;
                };
                let builder_index = id_to_builder[&r.reference_id];
                if let PresentationBuilders::Commitment(commitment) = &builders[builder_index] {
                    if let ClaimData::Number(n) = sig
                        .claims
                        .get(r.claim)
                        .ok_or(Error::InvalidPresentationData(format!("range proof statement with id '{}' references claim '{}' which doesn't exist", id, r.claim)))?
                    {
                        let builder =
                            RangeBuilder::commit(r, commitment, n.value, &mut transcript)?;
                        range_builders.push(builder.into());
                    } else {
                        return Err(Error::InvalidPresentationData(format!("range proof statement with id '{}' references claim '{}' which is not a number claim", id, r.claim)));
                    }
                } else {
                    return Err(Error::InvalidPresentationData(format!("range proof statement with id '{}' references a commitment '{}' that doesn't exist", id, r.reference_id)));
                }
            }
        }
        let mut okm = [0u8; 64];
        transcript.challenge_bytes(b"challenge bytes", &mut okm);
        let challenge = Scalar::from_bytes_wide(&okm);

        let mut proofs = IndexMap::new();

        for builder in range_builders.into_iter() {
            let proof = builder.gen_proof(challenge);
            proofs.insert(proof.id().clone(), proof);
        }
        for builder in builders.into_iter() {
            let proof = builder.gen_proof(challenge);
            proofs.insert(proof.id().clone(), proof);
        }
        let presentation = Self {
            proofs,
            challenge,
            disclosed_messages,
        };
        debug!(
            "Presentation: {}",
            serde_json::to_string(&presentation).unwrap()
        );
        Ok(presentation)
    }
}
