use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
// use pyo3::types::PyBytes;

#[pyclass]
struct PyTWCA {
    twca: rsca::TWCA,
}

#[derive(Debug)]
struct PyTWCAError(rsca::TWCAError);

impl std::convert::From<rsca::TWCAError> for PyTWCAError {
    fn from(err: rsca::TWCAError) -> PyTWCAError {
        PyTWCAError(err)
    }
}

impl std::convert::From<PyTWCAError> for PyErr {
    fn from(err: PyTWCAError) -> PyErr {
        PyValueError::new_err(err.0.to_string())
    }
}

#[pymethods]
impl PyTWCA {
    #[new]
    fn new(path: &str, password: &str, ip: &str) -> Result<Self, PyTWCAError> {
        let twca = rsca::TWCA::new(path, password, ip)?;
        Ok(PyTWCA { twca })
    }

    fn init_logger(&self) {
        tracing_subscriber::fmt::init();
    }

    fn get_cert_person_id(&self) -> Result<String, PyTWCAError> {
        Ok(self.twca.get_cert_person_id()?)
    }

    fn is_activate(&self) -> bool {
        true
    }

    fn get_expire_timestamp(&self) -> Result<i64, PyTWCAError> {
        Ok(self.twca.get_expire_time()?.timestamp())
    }

    fn _sign(&self, plain_text: &str) -> Result<String, PyTWCAError> {
        Ok(self.twca._sign(&plain_text.as_bytes())?)
    }

    fn get_quote_sign(&self, plain_text: &str) -> Result<String, PyTWCAError> {
        Ok(self.twca.get_quote_sign(&plain_text)?)
    }

    fn sign(&self, plain_text: &str) -> Result<String, PyTWCAError> {
        Ok(self.twca.sign(&plain_text)?)
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
