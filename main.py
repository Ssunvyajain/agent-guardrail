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


def real_path(path, base):

    path = unquote(path)

    if os.path.isabs(path):
        return os.path.normpath(path)

    return os.path.normpath(
        os.path.join(base, path)
    )


def inside(path, root):

    path = os.path.normpath(path)
    root = os.path.normpath(root)

    return path == root or path.startswith(root + os.sep)



def secret_read(command):

    c = command.lower()


    # Remove common escaping / quoting
    normalized = re.sub(
        r"[\s\"'\\]+",
        "",
        c
    )


    # Direct and normalized paths
    if (
        "/home/agent/.bashrc" in normalized
        or "home/agent/.bashrc" in normalized
    ):
        return True


    # Relative traversal cases
    relative_patterns = [
        r"\.\./\.bashrc",
        r"\./\.bashrc",
        r"\.\./.*/\.bashrc",
        r"cat\s+\.bashrc",
        r"cat\s+\./\.bashrc"
    ]

    for pattern in relative_patterns:
        if re.search(pattern, c):
            return True


    # Home shortcuts
    if (
        "~/.bashrc" in c
        or "$home/.bashrc" in c
        or "${home}/.bashrc" in c
    ):
        return True


    # Environment variable tricks
    if ".bashrc" in c and (
        "$home" in c
        or "${home}" in c
        or "$HOME" in command
        or "~" in c
    ):
        return True


    # Base64 payloads
    for token in command.split():

        try:

            decoded = base64.b64decode(
                token + "==="
            ).decode(
                errors="ignore"
            ).lower()


            if ".bashrc" in decoded:
                return True


        except Exception:
            pass


    # Any remaining bashrc reference
    # catches ../.bashrc after shell expansion attempts
    if ".bashrc" in c:
        return True


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

        if secret_read(command):

            return {
                "decision":"block",
                "reason":"Protected secret file access denied."
            }


        return {
            "decision":"allow",
            "reason":"Command allowed."
        }



    if tool == "write_file":

        path = data.get(
            "path",
            ""
        )

        resolved = real_path(
            path,
            WRITE_ROOT
        )


        if inside(
            resolved,
            WRITE_ROOT
        ):

            return {
                "decision":"allow",
                "reason":"Write path allowed."
            }


        return {
            "decision":"block",
            "reason":"Write outside allowed directory."
        }



    if tool == "http_request":

        host = urlparse(
            data.get("url","")
        ).hostname


        if host in ALLOWED_HOSTS:

            return {
                "decision":"allow",
                "reason":"Allowed host."
            }


        return {
            "decision":"block",
            "reason":"Host blocked."
        }



    return {
        "decision":"block",
        "reason":"Unknown tool."
    }