use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyclass]
struct PyTWCA {
    twca: rsca::TWCA
}

#[pymethods]
impl PyTWCA {
    #[new]
    fn new(path: &str, password: &str) -> Self {
        let twca = rsca::TWCA::new(path, password).unwrap();
        PyTWCA { twca }
    }

    fn get_person_id(&self) -> PyResult<String> {
        Ok(self.twca.get_common_name().unwrap())
    }
}

/// Formats the sum of two numbers as string.
#[pyfunction]
fn sign(path: &str, password: &str) -> PyResult<String> {
    let der = std::fs::read(path).unwrap();
    let cert = rsca::load_cert(&der, password).unwrap();
    let data = b"1234567890";
    let sign_data = rsca::sign(cert, data).unwrap();
    // sign_data
    // let signed = sign_data.to().unwrap();
    // PyBytes::new(py, &signed).into()
    Ok(sign_data)
}

/// A Python module implemented in Rust.
#[pymodule]
fn pyrsca(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_class::<PyTWCA>()?;
    Ok(())
}