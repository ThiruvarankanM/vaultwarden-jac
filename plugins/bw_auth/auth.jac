import json;
import os;
import hmac;
import hashlib;
import base64;
import time;
import from stdjac.server { Auth, SignIn, Session, Rejected }
import from stdjac.plan { data_dir }

obj BwAuth(Auth) {
    has issuer: str = "http://localhost|login";

    def open;

    def caller(headers: dict[str, str]) -> str | None;

    def asks(headers: dict[str, str]) -> SignIn;

    def answer(action: str, given: dict[str, str], client: str) -> Session;

    def leave(headers: dict[str, str]);
}

def unb64(s: str) -> bytes;

def subject(token: str, iss: str) -> str | None;
