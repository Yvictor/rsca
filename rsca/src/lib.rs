use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::X509;
use std::time::SystemTimeError;
// use base64::{Engine as _, engine::general_purpose};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use snafu::prelude::Snafu;
use snafu::{OptionExt, ResultExt};
use speedate::DateTime;
use tracing::info;
// use tracing_subscriber;

#[derive(Debug, Snafu)]
pub enum TWCAError {
    #[snafu(display("Ca Path Not Found {path}"))]
    PathNotFound { path: String },
    #[snafu(display("OpenSSL Error {}", source))]
    OpensslError { source: ErrorStack },
    #[snafu(display("SystemTime Error {}", source))]
    SystemTime { source: SystemTimeError },
    #[snafu(display("Datetime Parse Error {error}"))]
    DatetimeParse { error: String },
    #[snafu(display("ReadFile Error {}", source))]
    ReadFile { source: std::io::Error },
    #[snafu(display("Ca Password Incorrect"))]
    CaPasswordError { source: ErrorStack },
    #[snafu(display("Cert Not Found"))]
    CertNotFound {},
    #[snafu(display("PKey Not Found"))]
    PKeyNotFound {},
    #[snafu(display("Cert CN Not Found"))]
    CertCNNotFound {},
    #[snafu(display("Cert Person ID Not Found"))]
    CertPersonIdNotFound {},
}
#[derive(Debug)]
pub struct TWCA {
    cert: X509,
    pkey: PKey<Private>,
    fix_content: String,
}

fn get_cert_person_id(cert: &X509) -> Result<String, TWCAError> {
    let sub = cert.subject_name();
    match sub.entries_by_nid(Nid::COMMONNAME).nth(0) {
        Some(cn) => {
            let cn = cn
                .data()
                .as_utf8()
                .context(OpensslSnafu {})?
                .to_string()
                .split("-")
                .nth(0)
                .context(CertCNNotFoundSnafu {})?
                .to_string();
            Ok(cn)
        }
        None => Err(TWCAError::CertPersonIdNotFound {}),
    }
}

impl TWCA {
    pub fn new(path: &str, password: &str, ip: &str) -> Result<Self, TWCAError> {
        // let _provider =
            // openssl::provider::Provider::try_load(None, "legacy", true).context(OpensslSnafu {})?;
        let der = std::fs::read(path).context(ReadFileSnafu {})?;
        let p12 = Pkcs12::from_der(&der).context(OpensslSnafu {})?;
        let parsed_p12 = p12.parse2(&password).context(CaPasswordSnafu {})?;
        let cert = parsed_p12.cert.context(CertNotFoundSnafu {})?;
        let pkey = parsed_p12.pkey.context(PKeyNotFoundSnafu {})?;
        let person_id = get_cert_person_id(&cert)?;
        let fix_content = format!("{}{}", person_id, ip);
        Ok(TWCA {
            cert,
            pkey,
            fix_content,
        })
    }

    pub fn get_cert_person_id(&self) -> Result<String, TWCAError> {
        get_cert_person_id(&self.cert)
    }

    pub fn get_expire_time(&self) -> Result<DateTime, TWCAError> {
        // let t = self.cert.not_after();
        let t = Asn1Time::from_unix(0)
            .context(OpensslSnafu {})?
            .diff(self.cert.not_after())
            .context(OpensslSnafu {})?;
        match DateTime::from_timestamp(t.days as i64 * 86400 + t.secs as i64, 0) {
            Ok(dt) => Ok(dt),
            Err(e) => Err(TWCAError::DatetimeParse {
                error: e.to_string(),
            }),
        }
    }

    pub fn _sign(&self, data: &[u8]) -> Result<String, TWCAError> {
        info!("new stack");
        let certs = Stack::new().context(OpensslSnafu {})?;
        info!("sign");
        let sign = Pkcs7::sign(&self.cert, &self.pkey, &certs, &data, Pkcs7Flags::BINARY)
            .context(OpensslSnafu {})?;
        info!("signed done to pem");
        let der = sign.to_pem().context(OpensslSnafu {})?;
        info!("to pem done");
        let ss: Vec<&str> = std::str::from_utf8(&der).unwrap().split("\n").collect();
        info!("split");
        let s = ss.get(1..ss.len() - 2).unwrap().join("");
        info!("done");
        Ok(s)
    }

    pub fn get_quote_sign(&self, plain_text: &str) -> Result<String, TWCAError> {
        Ok(utf8_percent_encode(&self._sign(&plain_text.as_bytes())?, NON_ALPHANUMERIC).to_string())
    }

    pub fn sign(&self, plain_text: &str) -> Result<String, TWCAError> {
        info!("now");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .context(SystemTimeSnafu {})?;
        info!("get now done.");
        self.get_quote_sign(&format!(
            "{}{}{}",
            self.fix_content,
            plain_text,
            now.as_secs()
        ))
    }
}
pub fn load_cert(der: &[u8], password: &str) -> Option<ParsedPkcs12_2> {
    let res = Pkcs12::from_der(&der);
    match res {
        Ok(pkcs12) => {
            let res_pkcs12 = pkcs12.parse2(&password);
            match res_pkcs12 {
                Ok(parsed) => {
                    // println!("Parsed: {:?}", parsed.pkey);
                    Some(parsed)
                }
                Err(e) => {
                    println!("Error: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            println!("Error: {}", e);
            None
        }
    }
}

pub fn sign(pkcs12: ParsedPkcs12_2, data: &[u8]) -> Option<String> {
    let certs = Stack::new().unwrap();
    let cert = pkcs12.cert.unwrap();
    // let issuer_name = format!("{:?}", cert.issuer_name());
    // println!("{}", issuer_name);
    println!("{:?}", cert);
    // cert.subject_name().
    // let a = cert.not_after();
    // certs.push(cert.to_owned()).unwrap();
    let sign = Pkcs7::sign(
        &cert,
        &pkcs12.pkey.unwrap(),
        &certs,
        // &pkcs12.ca.unwrap(),
        &data,
        Pkcs7Flags::BINARY,
    );
    match sign {
        Ok(signed) => {
            let der = signed.to_pem().unwrap();
            // let s =general_purpose::URL_SAFE_NO_PAD.encode(&der);
            let ss: Vec<&str> = std::str::from_utf8(&der).unwrap().split("\n").collect();
            let s = ss.get(1..ss.len() - 2).unwrap().join("");
            Some(s)
        }
        Err(e) => {
            println!("Error: {}", e);
            None
        }
    }
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_works() {
        let path = std::env::var("PFX_PATH").unwrap_or(String::from("Sinopac.pfx"));
        let password = std::env::var("PFX_PASSWORD").unwrap_or(String::from(""));
        let ca = TWCA::new(&path, &password, "127.0.0.1").unwrap();
        println!("{:?}", ca);
        let person_id = ca.get_cert_person_id().unwrap();
        println!("{}", person_id);
        let expire_time = ca.get_expire_time().unwrap();
        println!("{}", expire_time.to_string());
        let signed = ca._sign(b"test").unwrap();
        println!("{}", signed);
        // let der = std::fs::read("Sinopac.pfx").unwrap();
        // let cert = load_cert(&der, &password);
        // // println!("{:?}", cert);
        // assert!(cert.is_some());
        // match cert {
        //     Some(cert) => {
        //         assert!(cert.pkey.is_some());
        //         assert!(cert.cert.is_some());
        //         // assert!(cert.ca.is_some());
        //         let data = b"1234567890";
        //         let sign_data = sign(cert, data);
        //         assert!(sign_data.is_some());
        //         // let signed = sign_data.unwrap();
        //         // println!("{:?}", signed.to_der());
        //     }
        //     None => {
        //         panic!("cert is None")
        //     }
        // }
        // let data = b"1234567890";
        // let sign_data = sign(cert.unwrap(), data);
        // assert!(sign_data.is_some());
    }
}
