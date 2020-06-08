import * as wasm from "vade-tnt";

//wasm.watch_event("127.0.0.1")
//wasm.send_extrinsic("127.0.0.1", Date.now() )
const sleep = m => new Promise(r => setTimeout(r, m))

//wasm.get_did("127.0.0.1", "0xa32c7b5e280e0ab04a44e44b7f17f64ecef2a8bbbc872c3564a09661ed6a3755")
//wasm.watch_event("13.69.59.185")
//wasm.send_extrinsic("13.69.59.185")
console.dir(wasm)

//wasm.get_did("13.69.59.185", "0xf63e1007dcc77614ae6f936a4c24e6a3e1ffefafeb51c1fde640cfe8b5650ece").then(res => console.dir(res))
console.dir(wasm.create_master_secret())
wasm.create_schema().then(async res => {
  const schema = JSON.parse(res);

  const cred_def = await wasm.create_credential_definition(schema.id);
  const cred_def_parsed = JSON.parse(cred_def);
  console.dir(cred_def_parsed);
  const proof = await wasm.request_proof(schema.id);
  const ms = wasm.create_master_secret();
  const proposal = await wasm.create_credential_proposal(schema.id);
  const offer = await wasm.create_credential_offer(proposal,cred_def_parsed[0].id);
  const request = await wasm.create_credential_request(JSON.stringify(cred_def_parsed[0]), offer, ms);
  const request_parsed = JSON.parse(request);
  const rev_reg = await wasm.create_revocation_registry_definition(cred_def_parsed[0].id, 42);
  console.log('---------------------------------')
  console.dir(JSON.parse(rev_reg));
  const rev_reg_parsed = JSON.parse(rev_reg);
  const iss_cred = await wasm.issue_credential(
    JSON.stringify(cred_def_parsed[0]),
    JSON.stringify(cred_def_parsed[1]),
    JSON.stringify(request_parsed[0]), 
    JSON.stringify(rev_reg_parsed.privateKey),
    JSON.stringify(rev_reg_parsed.revocationInfo),
    JSON.stringify(rev_reg_parsed.revocationRegistryDefinition),
    JSON.stringify(request_parsed[1]),
    ms
  );
  
  const iss_cred_parsed = JSON.parse(iss_cred);
  
  const present_proof = await wasm.present_proof(
    proof,
    JSON.stringify(iss_cred_parsed.credential),
    JSON.stringify(cred_def_parsed[0]),
    JSON.stringify(schema),
    JSON.stringify(rev_reg_parsed.revocationRegistryDefinition),
    ms
  );

  const verify_proof = await wasm.verify_proof(
    present_proof,
    proof,
    JSON.stringify(cred_def_parsed[0]),
    JSON.stringify(schema),
    JSON.stringify(rev_reg_parsed.revocationRegistryDefinition),
  )


/*
  let schema: CredentialSchema = create_credential_schema(&mut vade).await?;
  let (definition, credential_private_key) = create_credential_definition(&mut vade, &schema).await?;
  let proof_request: ProofRequest = request_proof(&mut vade, &schema).await?;
  let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();
  let proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;
  let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal, &definition).await?;
  let (request, blinding_factors) = create_credential_request(&mut vade, &definition, &offer, &master_secret).await?;


  //let (revocation_registry_definition, revocation_key_private, revocation_info):
  //(RevocationRegistryDefinition, RevocationKeyPrivate, RevocationIdInformation)
  let rev_reg_def: CreateRevocationRegistryDefinitionResult
      = create_revocation_registry_definition(&mut vade, &definition, 42).await?;
  let (mut credential, _): (Credential, _) = issue_credential(
      &mut vade, &definition,
      &credential_private_key,
      &request,
      &rev_reg_def.private_key,
      &rev_reg_def.revocation_info,
      &rev_reg_def.revocation_registry_definition
  ).await?;

  Prover::post_process_credential_signature(
    &mut credential,
    &request,
    &definition,
    blinding_factors,
    &master_secret,
    &rev_reg_def.revocation_registry_definition
  );

  let presented_proof: ProofPresentation = present_proof(
      &mut vade,
      &proof_request,
      &credential,
      &definition,
      &schema,
      &rev_reg_def.revocation_registry_definition,
      &master_secret,
  ).await?;

  // run test
  let result: ProofVerification = verify_proof(
      &mut vade,
      &presented_proof,
      &proof_request,
      &definition,
      &schema,
      &rev_reg_def.revocation_registry_definition
  ).await?;
  println!("{}", serde_json::to_string(&result).unwrap());*/

  console.dir(cred_def);
  console.dir(proof)
})