node User {
    has uuid: str,
        email: str,
        name: str,
        akey: str = "",
        private_key: str = "",
        public_key: str = "",
        password_hash: str = "",
        salt: str = "",
        password_iterations: int = 600000,
        password_hint: str = "",
        security_stamp: str = "",
        key_id: str = "",
        kdf_type: int = 0,
        kdf_iter: int = 600000,
        kdf_memory: int | None = None,
        kdf_parallelism: int | None = None,
        avatar_color: str = "",
        created_us: int = 0,
        updated_us: int = 0;
}

node Device {
    has uuid: str,
        name: str,
        atype: int,
        refresh_token: str,
        created_us: int = 0,
        updated_us: int = 0;
}

node Folder {
    has uuid: str,
        name: str,
        created_us: int = 0,
        updated_us: int = 0;
}

node Cipher {
    has uuid: str,
        atype: int,
        name: str,
        notes: str = "",
        fields: str = "",
        data: str = "{}",
        password_history: str = "",
        key: str = "",
        reprompt: int | None = None,
        favorite: bool = False,
        deleted_us: int | None = None,
        archived_us: int | None = None,
        created_us: int = 0,
        updated_us: int = 0;
}

edge Uses: User --> Device {}

edge Holds: Folder --> Cipher {}

def user_by_email(email: str) -> User | None;

def user_by_id(uuid: str) -> User | None;

def account(bearer: str) -> User | None;

def touch(u: User);

def folder_of(c: Cipher) -> Folder | None;

def find_folder(uuid: str) -> Folder | None;

def find_cipher(uuid: str) -> Cipher | None;

def owned(c: Cipher) -> bool;

def account_keys(u: User) -> dict[str, any] | None;
