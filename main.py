from fastapi import FastAPI, Request
from urllib.parse import urlparse, unquote
import os
import base64
import re


app = FastAPI()


WRITE_ROOT = "/data/agent/outbox"

ALLOWED_HOSTS = {
    "pypi.org",
    "huggingface.co"
}


def resolve_path(path, base):

    # Decode URL encoding like %2e%2e
    path = unquote(path)

    if os.path.isabs(path):
        return os.path.realpath(path)

    return os.path.realpath(
        os.path.join(base, path)
    )


def inside(path, root):

    path = os.path.realpath(path)
    root = os.path.realpath(root)

    return (
        path == root
        or path.startswith(root + os.sep)
    )


def check_secret(command):

    c = command.lower()

    # Direct secret
    if "/home/agent/.bashrc" in c:
        return True


    # Home expansion tricks
    patterns = [
        "~/.bashrc",
        "$home/.bashrc",
        "${home}/.bashrc",
        "$home/.bashrc",
        "$env:home/.bashrc"
    ]

    for p in patterns:
        if p in c:
            return True


    # Remove spaces and quotes
    compact = re.sub(
        r"[\s\"']",
        "",
        c
    )

    if ".bashrc" in compact:
        if (
            "home" in compact
            or "$" in compact
            or "~" in compact
        ):
            return True


    # Base64 decode
    for word in c.split():

        try:
            decoded = base64.b64decode(
                word + "==="
            ).decode(
                errors="ignore"
            ).lower()

            if ".bashrc" in decoded:
                return True

        except Exception:
            pass


    return False



@app.post("/check")
async def check(request: Request):

    data = await request.json()

    tool = data.get("tool")


    if tool == "bash":

        command = data.get(
            "command",
            ""
        )

        if check_secret(command):

            return {
                "decision": "block",
                "reason": "Protected secret file access denied."
            }


        return {
            "decision": "allow",
            "reason": "Command allowed."
        }



    if tool == "write_file":

        path = data.get(
            "path",
            ""
        )

        resolved = resolve_path(
            path,
            WRITE_ROOT
        )


        if inside(
            resolved,
            WRITE_ROOT
        ):

            return {
                "decision": "allow",
                "reason": "Write path allowed."
            }


        return {
            "decision": "block",
            "reason": "Write outside allowed directory."
        }



    if tool == "http_request":

        url = data.get(
            "url",
            ""
        )

        host = urlparse(url).hostname


        if host in ALLOWED_HOSTS:

            return {
                "decision": "allow",
                "reason": "Allowed hostname."
            }


        return {
            "decision": "block",
            "reason": "Hostname blocked."
        }



    return {
        "decision": "block",
        "reason": "Unknown tool."
    }