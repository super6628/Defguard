use base64::{
    Engine,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct AmrClaims {
    #[serde(default)]
    amr: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MicrosoftClaims {
    tid: String,
    #[serde(default)]
    amr: Vec<String>,
}

fn decode_claims<T>(id_token: &str) -> Result<T, &'static str>
where
    T: serde::de::DeserializeOwned,
{
    let payload = id_token.split('.').nth(1).ok_or("invalid JWT format")?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| URL_SAFE.decode(payload))
        .map_err(|_| "invalid JWT payload")?;
    serde_json::from_slice(&decoded).map_err(|_| "invalid JWT claims")
}

pub fn microsoft_mfa_satisfied(id_token: &str, expected_tenant: &str) -> Result<(), &'static str> {
    let claims: MicrosoftClaims = decode_claims(id_token)?;
    if !claims.tid.eq_ignore_ascii_case(expected_tenant) {
        return Err("unexpected Microsoft tenant");
    }
    if claims.amr.iter().any(|method| {
        method.eq_ignore_ascii_case("mfa") || method.eq_ignore_ascii_case("ngcmfa")
    }) {
        Ok(())
    } else {
        Err("Microsoft MFA not satisfied")
    }
}

pub fn generic_mfa_satisfied(id_token: &str) -> Result<(), &'static str> {
    let claims: AmrClaims = decode_claims(id_token)?;
    if claims
        .amr
        .iter()
        .any(|method| method.eq_ignore_ascii_case("mfa"))
    {
        Ok(())
    } else {
        Err("MFA not satisfied")
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::{generic_mfa_satisfied, microsoft_mfa_satisfied};

    fn token(payload: &str) -> String {
        format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(payload))
    }

    #[test]
    fn microsoft_accepts_mfa() {
        let token = token(r#"{"tid":"11111111-1111-1111-1111-111111111111","amr":["pwd","mfa"]}"#);
        assert!(microsoft_mfa_satisfied(&token, "11111111-1111-1111-1111-111111111111").is_ok());
    }

    #[test]
    fn microsoft_accepts_ngcmfa() {
        let token = token(r#"{"tid":"11111111-1111-1111-1111-111111111111","amr":["ngcmfa"]}"#);
        assert!(microsoft_mfa_satisfied(&token, "11111111-1111-1111-1111-111111111111").is_ok());
    }

    #[test]
    fn microsoft_rejects_ambiguous_wiaormfa() {
        let token = token(r#"{"tid":"11111111-1111-1111-1111-111111111111","amr":["wiaormfa"]}"#);
        assert!(microsoft_mfa_satisfied(&token, "11111111-1111-1111-1111-111111111111").is_err());
    }

    #[test]
    fn microsoft_rejects_wrong_tenant() {
        let token = token(r#"{"tid":"22222222-2222-2222-2222-222222222222","amr":["mfa"]}"#);
        assert!(microsoft_mfa_satisfied(&token, "11111111-1111-1111-1111-111111111111").is_err());
    }

    #[test]
    fn generic_provider_accepts_mfa() {
        let token = token(r#"{"amr":["pwd","mfa"]}"#);
        assert!(generic_mfa_satisfied(&token).is_ok());
    }

    #[test]
    fn generic_provider_fails_closed_without_mfa() {
        let token = token(r#"{"amr":["pwd"]}"#);
        assert!(generic_mfa_satisfied(&token).is_err());
    }

    #[test]
    fn malformed_token_fails_closed() {
        assert!(generic_mfa_satisfied("not-a-jwt").is_err());
    }
}
