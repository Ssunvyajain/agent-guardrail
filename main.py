from fastapi import FastAPI, Request
from urllib.parse import urlparse
import os


app = FastAPI()


WRITE_ROOT = "/data/agent/outbox"

ALLOWED_HOSTS = {
    "pypi.org",
    "huggingface.co"
}


def normalize(path):

    if not os.path.isabs(path):
        path = os.path.join(
            "/home/agent/workspace",
            path
        )

    return os.path.normpath(path)



def inside(path, root):

    path = os.path.normpath(path)
    root = os.path.normpath(root)

    return (
        path == root
        or path.startswith(root + os.sep)
    )



@app.post("/check")
async def check(request: Request):

    data = await request.json()

    tool = data.get("tool")


    # bash checking
    if tool == "bash":

        command = data.get("command","").lower()


        forbidden = [
            ".bashrc",
            "/home/agent/.bashrc",
            "~/.bashrc",
            "$home/.bashrc"
        ]


        for item in forbidden:
            if item in command:
                return {
                    "decision":"block",
                    "reason":"Protected secret file access denied."
                }


        return {
            "decision":"allow",
            "reason":"Command allowed."
        }



    # file writing
    if tool == "write_file":

        path = normalize(
            data.get("path","")
        )


        if inside(path, WRITE_ROOT):

            return {
                "decision":"allow",
                "reason":"Write location allowed."
            }


        return {
            "decision":"block",
            "reason":"Write outside allowed directory."
        }



    # HTTP requests
    if tool == "http_request":

        url = data.get("url","")

        host = urlparse(url).hostname


        if host in ALLOWED_HOSTS:

            return {
                "decision":"allow",
                "reason":"Allowed hostname."
            }


        return {
            "decision":"block",
            "reason":"Hostname blocked."
        }



    return {
        "decision":"block",
        "reason":"Unknown tool."
    }