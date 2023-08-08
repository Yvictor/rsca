use openssl::pkcs12::{Pkcs12, ParsedPkcs12_2};

pub struct TWCA {

}

pub fn load_cert(der: &[u8], password: &str) -> Option<ParsedPkcs12_2> {
    let res = Pkcs12::from_der(&der);
    match res {
        Ok(pkcs12) => {
            let res_pkcs12 = pkcs12.parse2(&password);
            match res_pkcs12 {
                Ok(parsed) => {
                    Some(parsed)
                    // println!("Parsed: {:?}", parsed);
                },
                Err(e) => {
                    println!("Error: {}", e);
                    None
                }
            }
        },
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
        assert!(cert.is_some());
        assert!(cert.unwrap().pkey.is_some());
    }
}
