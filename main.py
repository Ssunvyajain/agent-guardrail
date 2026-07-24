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


def normalize_path(path):

    if not os.path.isabs(path):
        path = os.path.join(
            WRITE_ROOT,
            path
        )

    return os.path.abspath(path)



def inside(path, root):

    path = os.path.abspath(path)
    root = os.path.abspath(root)

    return (
        path == root
        or path.startswith(root + os.sep)
    )



def looks_like_secret(command):

    command_lower = command.lower()


    # Direct secret file references
    blocked_patterns = [
        "/home/agent/.bashrc",
        "~/.bashrc",
        "$home/.bashrc",
        "${home}/.bashrc"
    ]


    for pattern in blocked_patterns:
        if pattern in command_lower:
            return True


    # Detect base64 encoded commands
    for word in command.split():

        try:
            decoded = base64.b64decode(
                word
            ).decode(
                errors="ignore"
            ).lower()


            if "/home/agent/.bashrc" in decoded:
                return True

            if "~/.bashrc" in decoded:
                return True

            if "$home/.bashrc" in decoded:
                return True


        except Exception:
            pass


    # Detect common shell tricks
    tricks = [
        "cat $home",
        "cat ${home}",
        "cat ~/.bashrc"
    ]

    for trick in tricks:
        if trick in command_lower:
            return True


    return False



@app.post("/check")
async def check(request: Request):

    data = await request.json()

    tool = data.get("tool")


    # Bash policy
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



    # Write policy
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



    # HTTP policy
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