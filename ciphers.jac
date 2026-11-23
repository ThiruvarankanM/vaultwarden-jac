def:protect list_ciphers(bearer: str) -> Reply;

def:protect read_cipher(id: str, bearer: str) -> Reply;

def:protect add_cipher(body: str, bearer: str) -> Reply;

def:protect add_shared_cipher(body: str, bearer: str) -> Reply;

def:protect edit_cipher(id: str, body: str, bearer: str) -> Reply;

def:protect trash_cipher(id: str, bearer: str) -> Reply;

def:protect drop_cipher(id: str, bearer: str) -> Reply;

def:protect restore_cipher(id: str, bearer: str) -> Reply;

def cipher_json(c: Cipher) -> dict[str, any];
