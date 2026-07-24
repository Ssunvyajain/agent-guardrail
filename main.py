from fastapi import FastAPI, Request
from urllib.parse import urlparse
import os
import base64
import re


app = FastAPI()


WRITE_ROOT = "/data/agent/outbox"
WORKSPACE = "/home/agent/workspace"

ALLOWED_HOSTS = {
    "pypi.org",
    "huggingface.co"
}


def normalize_path(path):

    # Absolute path
    if os.path.isabs(path):
        return os.path.normpath(path)

    # Relative paths come from agent workspace
    return os.path.normpath(
        os.path.join(
            WORKSPACE,
            path
        )
    )


def inside(path, root):

    path = os.path.normpath(path)
    root = os.path.normpath(root)

    return (
        path == root
        or path.startswith(root + os.sep)
    )


def looks_like_secret(command):

    c = command.lower()

    # remove spaces to catch split tricks
    compact = c.replace(" ", "")


    direct_patterns = [
        "/home/agent/.bashrc",
        "~/.bashrc",
        "$home/.bashrc",
        "${home}/.bashrc",
        "$env:home\\.bashrc",
        "bashrc"
    ]


    for p in direct_patterns:

        if p in c or p in compact:
            return True


    # Try decoding base64 parts
    for word in command.split():

        try:

            decoded = base64.b64decode(
                word + "===",
                validate=False
            ).decode(
                errors="ignore"
            ).lower()


            if ".bashrc" in decoded:
                return True


            if "/home/agent" in decoded and "bash" in decoded:
                return True


        except Exception:
            pass


    return False



@app.post("/check")
async def check(request: Request):

    data = await request.json()

    tool = data.get("tool")


    # --------------------
    # Bash policy
    # --------------------
    if tool == "bash":

        command = data.get(
            "command",
            ""
        )


        if looks_like_secret(command):

            return {
                "decision": "block",
                "reason": "Protected secret file access denied."
            }


        return {
            "decision": "allow",
            "reason": "Command allowed."
        }



    # --------------------
    # Write policy
    # --------------------
    if tool == "write_file":

        path = normalize_path(
            data.get(
                "path",
                ""
            )
        )


        if inside(
            path,
            WRITE_ROOT
        ):

            return {
                "decision": "allow",
                "reason": "Write location allowed."
            }


        return {
            "decision": "block",
            "reason": "Write outside allowed directory."
        }



    # --------------------
    # HTTP policy
    # --------------------
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