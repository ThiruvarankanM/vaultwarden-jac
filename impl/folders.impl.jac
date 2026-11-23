import json;
import from stdjac.graph { remove }

glob folder_spec: dict[str, any] = {"name": "str", "id": "str?"};

impl folder_json(f: Folder) -> dict[str, any] {
    return {"id": f.uuid, "name": f.name, "object": "folder", "revisionDate": fmt_date(f.updated_us)};
}

impl list_folders(bearer: str) -> Reply {
    return ok({"data": [folder_json(f) for f in [root --> [?:Folder]]], "object": "list", "continuationToken": None});
}

impl read_folder(id: str, bearer: str) -> Reply {
    f = find_folder(id);
    if f is None {
        return err("Invalid folder");
    }
    return ok(folder_json(f));
}

impl add_folder(body: str, bearer: str) -> Reply {
    u = account(bearer);
    if u is None {
        return err("Invalid user");
    }
    data = json.loads(body);
    if not fits(data, folder_spec) {
        return unprocessable();
    }
    now = now_us();
    f = Folder(uuid=new_uuid(), name=data["name"], created_us=now, updated_us=now);
    root ++> f;
    touch(u);
    return ok(folder_json(f));
}

impl edit_folder(id: str, body: str, bearer: str) -> Reply {
    data = json.loads(body);
    if not fits(data, folder_spec) {
        return unprocessable();
    }
    u = account(bearer);
    f = find_folder(id);
    if u is None or f is None {
        return err("Invalid folder");
    }
    f.name = data["name"];
    f.updated_us = now_us();
    touch(u);
    return ok(folder_json(f));
}

impl drop_folder(id: str, bearer: str) -> Reply {
    u = account(bearer);
    f = find_folder(id);
    if u is None or f is None {
        return err("Invalid folder");
    }
    remove(f);
    touch(u);
    return empty();
}
