use std::{net::IpAddr, str::FromStr};

use base64::{Engine, prelude::BASE64_STANDARD};
use chrono::NaiveDateTime;
pub use rcgen::ExtendedKeyUsagePurpose;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SigningKey, string::Ia5String,
};
use rustls_pki_types::{CertificateDer, CertificateSigningRequestDer, pem::PemObject};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use x509_parser::{
    extensions::{GeneralName, ParsedExtension},
    parse_x509_certificate,
};

const CA_NAME: &str = "S-Metric Secure CA";
const NOT_BEFORE_OFFSET_SECS: Duration = Duration::minutes(5);
const DEFAULT_CERT_VALIDITY_DAYS: i64 = 1825;
const WEB_HTTPS_CERT_VALIDITY_DAYS: i64 = 100;

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("Certificate generation error: {0}")]
    RCGenError(#[from] rcgen::Error),
    #[error("Failed to parse: {0}")]
    ParsingError(String),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("CSR hostname mismatch: {0}")]
    HostnameMismatch(String),
    #[error("CA certificate is not present; generate a CA first")]
    CaCertMissing,
    #[error("CA private key not available for signing")]
    CaKeyMissing,
}

pub struct CertificateAuthority<'a> {
    issuer: Issuer<'a, KeyPair>,
    cert_der: CertificateDer<'a>,
}

impl CertificateAuthority<'_> {
    pub fn from_ca_cert_pem(
        ca_cert_pem: &str,
        ca_key_pair: &str,
    ) -> Result<Self, CertificateError> {
        let key_pair = KeyPair::from_pem(ca_key_pair)?;
        let cert_der = CertificateDer::from_pem_slice(ca_cert_pem.as_bytes())
            .map_err(|e| CertificateError::ParsingError(e.to_string()))?;
        let issuer = Issuer::from_ca_cert_der(&cert_der, key_pair)?;
        Ok(Self { issuer, cert_der })
    }

    pub fn from_cert_der_key_pair(
        ca_cert_der: &[u8],
        ca_key_pair: &[u8],
    ) -> Result<Self, CertificateError> {
        let key_pair = KeyPair::try_from(ca_key_pair)?;
        let cert_der = CertificateDer::from(ca_cert_der.to_vec());
        let issuer = Issuer::from_ca_cert_der(&cert_der, key_pair)?;
        Ok(Self { issuer, cert_der })
    }

    pub fn from_key_cert_params(
        key_pair: KeyPair,
        ca_cert_params: CertificateParams,
    ) -> Result<Self, CertificateError> {
        let cert = ca_cert_params.self_signed(&key_pair)?;
        let issuer = Issuer::new(ca_cert_params, key_pair);
        let cert_der = cert.der().clone();
        Ok(Self { issuer, cert_der })
    }

    pub fn new(
        common_name: &str,
        email: &str,
        valid_for_days: u32,
    ) -> Result<Self, CertificateError> {
        let mut params = CertificateParams::new(vec![CA_NAME.to_string(), email.to_string()])?;
        params.distinguished_name.push(rcgen::DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
        params.not_before = OffsetDateTime::now_utc() - NOT_BEFORE_OFFSET_SECS;
        params.not_after = OffsetDateTime::now_utc() + Duration::days(i64::from(valid_for_days));
        let key_pair = KeyPair::generate()?;
        Self::from_key_cert_params(key_pair, params)
    }

    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    pub fn key_der(&self) -> Vec<u8> {
        self.issuer.key().serialize_der()
    }

    pub fn key_pem(&self) -> String {
        self.issuer.key().serialize_pem()
    }

    pub fn cert_pem(&self) -> String {
        pem::encode(&pem::Pem::new("CERTIFICATE", self.cert_der.to_vec()))
    }

    pub fn sign_csr(
        &self,
        csr_der: &[u8],
        valid_for_days: u32,
    ) -> Result<CertificateDer<'static>, CertificateError> {
        let csr = CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(
            csr_der.to_vec(),
        ))?;
        let mut params = csr.params;
        params.not_before = OffsetDateTime::now_utc() - NOT_BEFORE_OFFSET_SECS;
        params.not_after = OffsetDateTime::now_utc() + Duration::days(i64::from(valid_for_days));
        let cert = params.signed_by(&csr.public_key, &self.issuer)?;
        Ok(cert.der().clone())
    }

    pub fn sign_csr_default(
        &self,
        csr_der: &[u8],
    ) -> Result<CertificateDer<'static>, CertificateError> {
        self.sign_csr(csr_der, DEFAULT_CERT_VALIDITY_DAYS as u32)
    }

    pub fn sign_web_csr(
        &self,
        csr_der: &[u8],
    ) -> Result<CertificateDer<'static>, CertificateError> {
        self.sign_csr(csr_der, WEB_HTTPS_CERT_VALIDITY_DAYS as u32)
    }
}

pub struct Csr {
    params: CertificateParams,
    key_pair: KeyPair,
}

impl Csr {
    pub fn new(common_name: &str) -> Result<Self, CertificateError> {
        let mut params = CertificateParams::new(vec![common_name.to_owned()])?;
        params.distinguished_name.push(rcgen::DnType::CommonName, common_name);
        let key_pair = KeyPair::generate()?;
        Ok(Self { params, key_pair })
    }

    pub fn new_with_sans(common_name: &str, sans: &[String]) -> Result<Self, CertificateError> {
        let mut names = vec![common_name.to_owned()];
        names.extend_from_slice(sans);
        let mut params = CertificateParams::new(names)?;
        params.distinguished_name.push(rcgen::DnType::CommonName, common_name);
        let key_pair = KeyPair::generate()?;
        Ok(Self { params, key_pair })
    }

    pub fn serialize_der(&self) -> Result<Vec<u8>, CertificateError> {
        Ok(self.params.serialize_request(&self.key_pair)?.der().to_vec())
    }

    pub fn key_der(&self) -> Vec<u8> {
        self.key_pair.serialize_der()
    }

    pub fn key_pem(&self) -> String {
        self.key_pair.serialize_pem()
    }
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub common_name: String,
    pub subject_alt_names: Vec<String>,
    pub not_before: NaiveDateTime,
    pub not_after: NaiveDateTime,
}

impl CertificateInfo {
    pub fn from_der(cert_der: &[u8]) -> Result<Self, CertificateError> {
        let (_, cert) = parse_x509_certificate(cert_der)
            .map_err(|e| CertificateError::ParsingError(e.to_string()))?;
        let common_name = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or_default()
            .to_owned();
        let mut subject_alt_names = Vec::new();
        for ext in cert.extensions() {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(name) => subject_alt_names.push((*name).to_owned()),
                        GeneralName::IPAddress(bytes) => {
                            if let Ok(ip) = IpAddr::from_str(&bytes.iter().map(u8::to_string).collect::<Vec<_>>().join(".")) {
                                subject_alt_names.push(ip.to_string());
                            }
                        }
                        GeneralName::RFC822Name(email) => subject_alt_names.push((*email).to_owned()),
                        _ => {}
                    }
                }
            }
        }
        Ok(Self {
            common_name,
            subject_alt_names,
            not_before: cert.validity().not_before.to_datetime().into(),
            not_after: cert.validity().not_after.to_datetime().into(),
        })
    }
}

pub trait PemLabel {
    const LABEL: &'static str;
}

pub struct CoreClientCert;
impl PemLabel for CoreClientCert { const LABEL: &'static str = "CERTIFICATE"; }

pub fn der_to_pem<T: PemLabel>(der: &[u8]) -> String {
    pem::encode(&pem::Pem::new(T::LABEL, der.to_vec()))
}

pub fn pem_to_der(pem_str: &str) -> Result<Vec<u8>, CertificateError> {
    Ok(pem::parse(pem_str).map_err(|e| CertificateError::ParsingError(e.to_string()))?.contents().to_vec())
}

pub fn encode_base64(data: &[u8]) -> String {
    BASE64_STANDARD.encode(data)
}
