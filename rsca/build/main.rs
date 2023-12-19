extern crate openssl_src;
mod find_vendored;


#[derive(PartialEq)]
enum Version {
    Openssl3xx,
    Openssl11x,
    Openssl10x,
    Libressl,
    Boringssl,
}


fn env_inner(name: &str) -> Option<OsString> {
    let var = env::var_os(name);
    println!("cargo:rerun-if-env-changed={}", name);

    match var {
        Some(ref v) => println!("{} = {}", name, v.to_string_lossy()),
        None => println!("{} unset", name),
    }

    var
}

fn env(name: &str) -> Option<OsString> {
    let prefix = env::var("TARGET").unwrap().to_uppercase().replace('-', "_");
    let prefixed = format!("{}_{}", prefix, name);
    env_inner(&prefixed).or_else(|| env_inner(name))
}

fn find_openssl(target: &str) -> (Vec<PathBuf>, PathBuf) {
    find_vendored::get_openssl(target)
}


fn main() {
    let target = env::var("TARGET").unwrap();
    let (lib_dirs, include_dir) = find_openssl(&target);

    if !lib_dirs.iter().all(|p| Path::new(p).exists()) {
        panic!("OpenSSL library directory does not exist: {:?}", lib_dirs);
    }
    if !Path::new(&include_dir).exists() {
        panic!(
            "OpenSSL include directory does not exist: {}",
            include_dir.to_string_lossy()
        );
    }

    for lib_dir in lib_dirs.iter() {
        println!(
            "cargo:rustc-link-search=native={}",
            lib_dir.to_string_lossy()
        );
    }
    println!("cargo:include={}", include_dir.to_string_lossy());

}



