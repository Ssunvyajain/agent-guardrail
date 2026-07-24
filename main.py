from fastapi import FastAPI, Request
from urllib.parse import urlparse
import os
import base64
import shlex


app = FastAPI()


WRITE_ROOT = "/data/agent/outbox"
SECRET_FILE = "/home/agent/.bashrc"

ALLOWED_HOSTS = {
    "pypi.org",
    "huggingface.co"
}


def normalize_path(path, base=None):

    if os.path.isabs(path):
        return os.path.normpath(path)

    return os.path.normpath(
        os.path.join(base, path)
    )


def is_inside(path, root):

    path = os.path.normpath(path)
    root = os.path.normpath(root)

    return (
        path == root
        or path.startswith(root + os.sep)
    )


def decode_possible_base64(text):

    results = []

    for word in text.split():

        try:
            decoded = base64.b64decode(
                word + "==="
            ).decode(
                "utf-8",
                errors="ignore"
            )

            results.append(decoded.lower())

        except Exception:
            pass

    return results



def is_secret_read(command):

    c = command.lower()


    # Direct secret references
    bad = [
        "/home/agent/.bashrc",
        "~/.bashrc",
        "$home/.bashrc",
        "${home}/.bashrc",
        "$home/.bashrc",
    ]

    for item in bad:
        if item in c:
            return True


    # Shell variable expansion patterns
    if ".bashrc" in c:

        if (
            "$home" in c
            or "${home}" in c
            or "~" in c
            or "/home/agent" in c
        ):
            return True


    # Decode base64 payloads
    for decoded in decode_possible_base64(command):

        if SECRET_FILE in decoded:
            return True

        if ".bashrc" in decoded and "home" in decoded:
            return True


    # Try extracting quoted commands
    try:

        parts = shlex.split(command)

        joined = " ".join(parts).lower()

        if SECRET_FILE in joined:
            return True

    except Exception:
        pass


    return False



@app.post("/check")
async def check(request: Request):

    data = await request.json()

    tool = data.get("tool")


    # -------------------------
    # Bash
    # -------------------------

    if tool == "bash":

        command = data.get(
            "command",
            ""
        )

        if is_secret_read(command):

            return {
                "decision": "block",
                "reason": "Reading protected secret file is forbidden."
            }


        return {
            "decision": "allow",
            "reason": "Command allowed."
        }



    # -------------------------
    # Write file
    # -------------------------

    if tool == "write_file":

        path = data.get(
            "path",
            ""
        )

        # Absolute paths are checked directly.
        # Relative paths are treated relative to write root.
        resolved = normalize_path(
            path,
            WRITE_ROOT
        )


        if is_inside(
            resolved,
            WRITE_ROOT
        ):

            return {
                "decision": "allow",
                "reason": "Write path is inside allowed directory."
            }


        return {
            "decision": "block",
            "reason": "Write path escapes allowed directory."
        }



    # -------------------------
    # HTTP
    # -------------------------

    if tool == "http_request":

        url = data.get(
            "url",
            ""
        )

        host = urlparse(url).hostname


        if host in ALLOWED_HOSTS:

            return {
                "decision": "allow",
                "reason": "Hostname is allowed."
            }


        return {
            "decision": "block",
            "reason": "Hostname is not allowed."
        }



    return {
        "decision": "block",
        "reason": "Unknown tool."
    }