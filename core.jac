def:pub alive -> Reply;

def:pub config -> Reply;

def:protect sync(query: str, bearer: str) -> Reply;

def:protect profile(bearer: str) -> Reply;

def:protect revision_date(bearer: str) -> Reply;

def:protect set_user_key_id(body: str, bearer: str) -> Reply;

def profile_json(u: User) -> dict[str, any];
