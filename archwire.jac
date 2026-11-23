graph layers {
    layer all { *; }
}

graph import {
    wire ++> model { now_us, verify }
    wire ++> identity {
        Reply,
        ok,
        err,
        unprocessable,
        fits,
        dumps,
        sign,
        verify,
        prelogin_index,
        opt,
        now_us,
        new_uuid,
    }
    model ++> identity { User, Device, Uses, user_by_email, account_keys }
    wire ++> core { Reply, ok, err, unprocessable, fits, empty, fmt_date, now_us, opt }
    model ++> core { User, Cipher, Folder, account, touch, account_keys }
    folders ++> core { folder_json }
    ciphers ++> core { cipher_json }
    wire ++> folders { Reply, ok, err, unprocessable, fits, empty, fmt_date, now_us, new_uuid }
    model ++> folders { Folder, account, touch, find_folder }
    wire ++> ciphers {
        Reply,
        ok,
        err,
        unprocessable,
        fits,
        empty,
        fmt_date,
        parse_date,
        now_us,
        new_uuid,
        opt,
    }
    model ++> ciphers {
        User,
        Cipher,
        Folder,
        Holds,
        account,
        touch,
        find_folder,
        find_cipher,
        owned,
        folder_of,
    }
}

graph spaces {
    space api: native { wire | model | identity | core | folders | ciphers; }

    app vaultwarden { run api; }
}
