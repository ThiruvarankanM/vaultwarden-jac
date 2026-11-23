def:protect list_folders(bearer: str) -> Reply;

def:protect read_folder(id: str, bearer: str) -> Reply;

def:protect add_folder(body: str, bearer: str) -> Reply;

def:protect edit_folder(id: str, body: str, bearer: str) -> Reply;

def:protect drop_folder(id: str, bearer: str) -> Reply;

def folder_json(f: Folder) -> dict[str, any];
