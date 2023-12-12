
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::X509;
// use base64::{Engine as _, engine::general_purpose};
use snafu::{ResultExt, OptionExt};
use snafu::prelude::Snafu;

#[derive(Debug, Snafu)]
pub enum TWCAError {
    #[snafu(display("Ca Path Not Found {path}"))]
    PathNotFound {
        path: String
    },
    #[snafu(display("OpenSSL Error {}", source))]
    OpensslError {
        source: ErrorStack
    },
    #[snafu(display("ReadFile Error {}", source))]
    ReadFile {
        source: std::io::Error
    },
    #[snafu(display("Cert Not Found"))]
    CertNotFound {},
    #[snafu(display("PKey Not Found"))]
    PKeyNotFound {},
}
#[derive(Debug)]
pub struct TWCA {
    cert: X509,
    pkey: PKey<Private>,
}

impl TWCA {

    pub fn new(path: &str, password: &str) -> Result<Self, TWCAError> {
        let der = std::fs::read(path).context(ReadFileSnafu {})?;
        let p12 = Pkcs12::from_der(&der).context(OpensslSnafu {})?;
        let parsed_p12 = p12.parse2(&password).context(OpensslSnafu {})?;
        let cert = parsed_p12.cert.context(CertNotFoundSnafu {})?;
        let pkey = parsed_p12.pkey.context(PKeyNotFoundSnafu {})?;
        Ok(TWCA { cert , pkey})
    }

    pub fn get_common_name(&self) -> Option<String> {
        let sub = self.cert.subject_name();
        match sub.entries_by_nid(Nid::COMMONNAME).nth(0) {
            Some(cn) => {
                let cn= cn.data().as_utf8().unwrap().to_string().split("-").nth(0).unwrap().to_string();
                Some(cn)
            }
            None => {
                None
            }
        }
    }

    pub fn get_expire_time(&self) -> String {
        format!("{}", self.cert.not_after())
    }

    pub fn sing(&self, data: &[u8]) -> Result<String, TWCAError> {
        let certs = Stack::new().context(OpensslSnafu {})?;
        let sign = Pkcs7::sign(&self.cert, &self.pkey, &certs, &data, Pkcs7Flags::BINARY).context(OpensslSnafu {})?;
        let der = sign.to_pem().context(OpensslSnafu {})?;
        let ss: Vec<&str> = std::str::from_utf8(&der).unwrap().split("\n").collect();
        let s = ss.get(1..ss.len()-2).unwrap().join("");
        Ok(s)  
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
            let s = ss.get(1..ss.len()-2).unwrap().join("");
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
        let password = "";
        let ca = TWCA::new("Sinopac.pfx", password).unwrap();
        println!("{:?}", ca);
        let person_id = ca.get_common_name().unwrap();
        println!("{}", person_id);
        let expire_time = ca.get_expire_time();
        println!("{}", expire_time);
        let signed = ca.sing(b"test").unwrap();
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
