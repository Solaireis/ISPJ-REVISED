"""
Run this file to download all dependencies with integrity checks.

Refer to: https://warehouse.pypa.io/api-reference/json.html
"""
# import python standard libraries
import hashlib
import shutil
import json
import platform
import sys
import os
import pathlib
import threading
from urllib.request import (
    Request, 
    urlopen,
)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
}

def download_file(url: str, file: pathlib.Path, length: int = 1024*1024) -> None:
    """
    Downloads a file from a url and saves it to a file.

    Args:
        url (str): 
            url of the file to download
        file (pathlib.Path): 
            the file path to save to
        length (int): 
            the length of each chunk of the file to download (in bits)
            Default: 1 MiB per chunk
    """
    req = urlopen(Request(url, headers=HEADERS), timeout=10)
    with open(file, "wb") as fp:
        # Note: this doesn't work with compressed files like gzip encoding
        shutil.copyfileobj(req, fp, length)

# initialising variables
ROOT_DIR = pathlib.Path(__file__).absolute().parent.parent
DIR_NAME = ROOT_DIR.joinpath("test_requirements.txt")
PACKAGE_DIR = ROOT_DIR.joinpath("python_packages")
PACKAGE_DIR.mkdir(parents=True, exist_ok=True)

# Get system type & sets PIP command
PLATFORM_TYPE = platform.system()
PIP_OS_COMMAND = "python3 -m pip install" if (PLATFORM_TYPE != "Windows") else "pip install"

# Get system's python version
PY_MAJOR_VER = sys.version_info[0]
PY_MINOR_VER = sys.version_info[1]
PY_VER = str(PY_MAJOR_VER) + str(PY_MINOR_VER) # will get 39, 310, etc.
print(f"Your Python version is: {PY_VER}. You're using a {PLATFORM_TYPE} system.")

class DependencyThread(threading.Thread):
    def __init__(self, lib: str):
        super().__init__()
        self.lib = lib
        self.exit_code = None

    def download_and_install(self) -> None:
        maximum = False
        sha256 = hashlib.sha256()

        version = self.lib.split("=")
        name = version[0].split(">")[0]
        version = version[-1].strip()
        try:
            version = version.split(",")[1].strip()
            maximum = True
        except:
            pass

        # TODO: Fix to deal with names with square brackets
        # print(f"https://pypi.org/pypi/{name}/json")
        data_file = json.load(urlopen(Request(f"https://pypi.org/pypi/{name}/json", headers=HEADERS), timeout=10))
        file = data_file["releases"]
        versions = list(file)

        for j in range(len(versions)-1, -1, -1):
            if not maximum:
                if versions[j] >= version:
                    version = versions[j]
                    break
            else:
                if versions[j] < version:
                    version = versions[j]
                    break

        try:
            file = data_file["releases"][version][2]
            for i in data_file["releases"][version]:
                url = i["url"]
                file = i
                if f"cp{PY_VER}" in url or f"pp{PY_VER}" in url:
                    if PLATFORM_TYPE == "Darwin":
                        if "macosx" in url:
                            break
                    elif PLATFORM_TYPE == "Linux":
                        if "linux" in url and "64" in url:
                            break
                    else:
                        # for Windows 64-bit machines
                        if "amd" in url and "64" in url:
                            break
        except:
            file = data_file["releases"][version][0]
            url = file["url"]

        filename = file["filename"]
        hashed = file["digests"]["sha256"]
        path = f"{PACKAGE_DIR}/{filename}"
        download_file(url, path)

        with open(path, "rb") as f:
            data = f.read()
            sha256.update(data)

        if sha256.hexdigest() != hashed:
            pathlib.Path(path).unlink(missing_ok=True)
            print(f"Dependency {self.lib} does not match the hash!")
            return 1

        os.system(f"{PIP_OS_COMMAND} {self.lib}")
        print(f"Dependency {self.lib} matches the hash! Successfully Installed & Deleted")
        pathlib.Path(path).unlink(missing_ok=True)
        return 0

    def run(self):
        self.exit_code = self.download_and_install()

def main() -> None:
    """
    Adds all dependencies to the python_packages folder and pip installs them.
    """
    dependencies = []
    with open(DIR_NAME) as f:
        for dependency in f:
            dependency = dependency.strip()
            if dependency and not dependency.startswith("#"):
                dependencies.append(dependency)

    threads = [DependencyThread(lib) for lib in dependencies]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    for thread in threads:
        if thread.exit_code != 0:
            return 1

    return 0

if (__name__ == "__main__"):
    return_code = main()
    print(f"Exiting with code: {return_code}")
    sys.exit(return_code)