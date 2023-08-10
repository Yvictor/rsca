use pyo3::prelude::*;


/// Formats the sum of two numbers as string.
#[pyfunction]
fn sum_as_string(a: usize, b: usize, password: &str) -> PyResult<String> {
    let der = std::fs::read("Sinopac.pfx").unwrap();
    let cert = rsca::load_cert(&der, password).unwrap();
    let data = b"1234567890";
    let _sign_data = rsca::sign(cert, data).unwrap();
    // sign_data
    Ok((a + b).to_string())
}

/// A Python module implemented in Rust.
#[pymodule]
fn pyrsca(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    Ok(())
}