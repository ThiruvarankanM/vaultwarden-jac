import json;
import os;
import hmac;
import hashlib;
import base64;
import time;
import from auth.contract { Auth, AuthHost, SignIn, Session, Rejected }

glob keys: dict[str, str] = {};

obj BwAuth(Auth) {
    has issuer: str = "http://localhost|login";

    def open(host: dyn AuthHost);

    def caller(headers: dict[str, str]) -> str | None;

    def asks(headers: dict[str, str]) -> SignIn;

    def answer(action: str, given: dict[str, str], client: str) -> Session;

    def leave(headers: dict[str, str]);
}

def unb64(s: str) -> bytes;

def subject(token: str, iss: str) -> str | None;
