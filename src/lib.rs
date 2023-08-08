use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
pub struct TWCA {}

pub fn load_cert(der: &[u8], password: &str) -> Option<ParsedPkcs12_2> {
    let res = Pkcs12::from_der(&der);
    match res {
        Ok(pkcs12) => {
            let res_pkcs12 = pkcs12.parse2(&password);
            match res_pkcs12 {
                Ok(parsed) => {
                    Some(parsed)
                    // println!("Parsed: {:?}", parsed);
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

pub fn sign(pkcs12: ParsedPkcs12_2, data: &[u8]) -> Option<Pkcs7> {
    let sign = Pkcs7::sign(
        &pkcs12.cert.unwrap(),
        &pkcs12.pkey.unwrap(),
        &pkcs12.ca.unwrap(),
        &data,
        Pkcs7Flags::BINARY,
    );
    match sign {
        Ok(signed) => {
            Some(signed)
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
        let der = std::fs::read("Sinopac.pfx").unwrap();
        let password = "";
        let cert = load_cert(&der, &password);
        // assert!(cert.is_some());
        // assert!(cert.unwrap().pkey.is_some());
        let data = b"1234567890";
        let sign_data = sign(cert.unwrap(), data);
        assert!(sign_data.is_some());
    }
}
