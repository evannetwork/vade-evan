use ssi::{
    jsonld::{json_to_dataset, JsonLdOptions, StaticLoader},
    urdna2015::normalize,
};
use thiserror::Error;
use vade_evan_bbs::{
    CredentialSchema,
    CredentialSchemaReference,
    CredentialStatus,
    CredentialSubject,
    PrefixedUuid,
    UnsignedBbsCredential,
};

#[derive(Error, Debug)]
pub enum SharedError {
    #[error("JSON-ld handling failed, {0}")]
    JsonLdHandling(String),
}

pub async fn convert_to_nquads(document_string: &str) -> Result<Vec<String>, SharedError> {
    let mut loader = StaticLoader;
    let options = JsonLdOptions {
        base: None,           // -b, Base IRI
        expand_context: None, // -c, IRI for expandContext option
        ..Default::default()
    };
    let dataset = json_to_dataset(
        &document_string,
        None, // will be patched into @context, e.g. Some(&r#"["https://schema.org/"]"#.to_string()),
        false,
        Some(&options),
        &mut loader,
    )
    .await
    .map_err(|err| SharedError::JsonLdHandling(err.to_string()))?;
    let dataset_normalized = normalize(&dataset).unwrap();
    let normalized = dataset_normalized.to_nquads().unwrap();
    let non_empty_lines = normalized
        .split("\n")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    Ok(non_empty_lines)
}

pub fn create_draft_credential_from_schema(
    use_valid_until: bool,
    schema: &CredentialSchema,
) -> UnsignedBbsCredential {
    let credential = UnsignedBbsCredential {
        context: vec![
            "https://www.w3.org/2018/credentials/v1".to_string(),
            "https://schema.org/".to_string(),
            "https://w3id.org/vc-revocation-list-2020/v1".to_string(),
        ],
        id: PrefixedUuid::new("uuid:834ca9da-9f09-4359-8264-c890de13cdc8".to_string()),
        r#type: vec!["VerifiableCredential".to_string()],
        issuer: "did:evan:testcore:placeholder_issuer".to_string(),
        valid_until: if use_valid_until {
            Some("2031-01-01T00:00:00.000Z".to_string())
        } else {
            None
        },
        issuance_date: "2021-01-01T00:00:00.000Z".to_string(),
        credential_subject: CredentialSubject {
            id: None,
            data: schema // fill ALL subject data fields with empty string (mandatory and optional ones)
                .properties
                .clone()
                .into_iter()
                .map(|(name, _schema_property)| (name, String::new()))
                .collect(),
        },
        credential_schema: CredentialSchemaReference {
            id: schema.id.to_owned(),
            r#type: schema.r#type.to_owned(),
        },
        credential_status: Some(CredentialStatus {
            id: "did:evan:zkp:placeholder_status#0".to_string(),
            r#type: "RevocationList2020Status".to_string(),
            revocation_list_index: "0".to_string(),
            revocation_list_credential: "did:evan:zkp:placeholder_status".to_string(),
        }),
    };
    credential
}

pub fn check_for_optional_empty_params(param: Option<&str>) -> Option<&str> {
    match param {
        Some(val) => {
            if val.is_empty() {
                None
            } else {
                Some(val)
            }
        }
        _ => None,
    }
}
