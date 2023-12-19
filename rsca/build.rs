use openssl_src;
use std::path::Path;

fn main() {
    println!("build openssl");

    let artifacts = openssl_src::Build::new().build();
    println!("cargo:vendored=1");
    println!(
        "cargo:root={}",
        artifacts.lib_dir().parent().unwrap().display()
    );

    let (lib_dirs, include_dir) = (
        vec![artifacts.lib_dir().to_path_buf()],
        artifacts.include_dir().to_path_buf(),
    );

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
