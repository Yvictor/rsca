class PyTWCA:
    """
    PyTWCA

    """

    def __init__(self, path: str, password: str, ip: str) -> None: ...
    def get_cert_person_id(self) -> str: ...
    def is_activate(self) -> bool: ...
    def get_expire_timestamp(self) -> int: ...
    def get_quote_sign(self, plain_text: str) -> str: ...
    def sign(self, plain_text: str) -> str: ...
    def get_cert_base64(self) -> str: ...
    def sign_pkcs1(self, plain_text: str) -> str: ...
    def init_logger(self) -> None: ...
