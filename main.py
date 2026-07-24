from fastapi import FastAPI, Request
from urllib.parse import urlparse
import os
import base64
import re


app = FastAPI()


WRITE_ROOT = "/data/agent/outbox"

ALLOWED_HOSTS = {
    "pypi.org",
    "huggingface.co"
}


def normalize_write_path(path):

    # Absolute paths stay absolute
    if os.path.isabs(path):
        return os.path.normpath(path)

    # Relative writes are relative to outbox
    return os.path.normpath(
        os.path.join(
            WRITE_ROOT,
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


def secret_access(command):

    c = command.lower()

    # Direct references
    checks = [
        "/home/agent/.bashrc",
        "~/.bashrc",
        "$home/.bashrc",
        "${home}/.bashrc",
        "$home/.bashrc"
    ]

    for x in checks:
        if x in c:
            return True


    # Environment expansion attempts
    if "home" in c and ".bashrc" in c:
        return True


    # Base64
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

        if secret_access(command):

            return {
                "decision": "block",
                "reason": "Protected secret file access denied."
            }


        return {
            "decision": "allow",
            "reason": "Command allowed."
        }



    if tool == "write_file":

        path = normalize_write_path(
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
                "reason": "Write allowed."
            }


        return {
            "decision": "block",
            "reason": "Write outside allowed directory."
        }



    if tool == "http_request":

        host = urlparse(
            data.get("url", "")
        ).hostname


        if host in ALLOWED_HOSTS:

            return {
                "decision": "allow",
                "reason": "Allowed host."
            }


        return {
            "decision": "block",
            "reason": "Host not allowed."
            }


    return {
        "decision": "block",
        "reason": "Unknown tool."
    }