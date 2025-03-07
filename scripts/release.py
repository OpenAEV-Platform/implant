import argparse
import logging
import os

import requests
from OBAS_utils.release_utils import check_release, closeRelease

logging.basicConfig(encoding="utf-8", level=logging.INFO)

parser = argparse.ArgumentParser("release")
parser.add_argument(
    "branch_implant", help="The new version number of the release.", type=str
)
parser.add_argument(
    "previous_version", help="The previous version number of the release.", type=str
)
parser.add_argument(
    "new_version", help="The new version number of the release.", type=str
)
parser.add_argument(
    "github_token", help="The github token to use for the release note.", type=str
)
parser.add_argument(
    "--dev", help="Flag to prevent pushing the release.", action="store_false"
)
args = parser.parse_args()

previous_version = args.previous_version
new_version = args.new_version
branch_implant = args.branch_implant
github_token = args.github_token

os.environ["DRONE_COMMIT_AUTHOR"] = "Filigran-Automation"
os.environ["GIT_AUTHOR_NAME"] = "Filigran Automation"
os.environ["GIT_AUTHOR_EMAIL"] = "automation@filigran.io"
os.environ["GIT_COMMITTER_NAME"] = "Filigran Automation"
os.environ["GIT_COMMITTER_EMAIL"] = "automation@filigran.io"

# Implant

logging.info("[implant] Starting the release")
logging.info("[implant] Searching and replacing all version numbers everywhere")

# Cargo.toml
with open("Cargo.toml", "r") as file:
    filedata = file.read()
filedata = filedata.replace(previous_version, new_version)
with open("Cargo.toml", "w") as file:
    file.write(filedata)

logging.info("[implant] Pushing to " + branch_implant)
os.system(
    'git commit -a -m "[implant] Release '
    + new_version
    + '" > /dev/null 2>&1 && git push origin '
    + branch_implant
    + " > /dev/null 2>&1"
)

logging.info("[implant] Tagging")
os.system("git tag -f " + new_version + " && git push -f --tags > /dev/null 2>&1")

check_release(
    "https://filigran.jfrog.io/ui/native/openbas-implant/linux/x86_64/",
    "openbas-implant-" + new_version,
)
check_release(
    "https://filigran.jfrog.io/ui/native/openbas-implant/linux/arm64/",
    "openbas-implant-" + new_version,
)
check_release(
    "https://filigran.jfrog.io/ui/native/openbas-implant/macos/x86_64/",
    "openbas-implant-" + new_version,
)
check_release(
    "https://filigran.jfrog.io/ui/native/openbas-implant/macos/arm64/",
    "openbas-implant-" + new_version,
)
check_release(
    "https://filigran.jfrog.io/ui/native/openbas-implant/windows/x86_64/",
    "openbas-implant-" + new_version,
)
check_release(
    "https://filigran.jfrog.io/ui/native/openbas-implant/windows/arm64/",
    "openbas-implant-" + new_version,
)

logging.info("[implant] Generating release")
os.system("gren release > /dev/null 2>&1")

# Modify the release note
logging.info("[implant] Getting the current release note")
release = requests.get(
    "https://api.github.com/repos/OpenBAS-Platform/implant/releases/latest",
    headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + github_token,
        "X-GitHub-Api-Version": "2022-11-28",
    },
)
release_data = release.json()
release_body = release_data["body"]

logging.info("[implant] Generating the new release note")
github_release_note = requests.post(
    "https://api.github.com/repos/OpenBAS-Platform/implant/releases/generate-notes",
    headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + github_token,
        "X-GitHub-Api-Version": "2022-11-28",
    },
    json={"tag_name": new_version, "previous_tag_name": previous_version},
)
github_release_note_data = github_release_note.json()
github_release_note_data_body = github_release_note_data["body"]
if "Full Changelog" not in release_body:
    new_release_note = (
        release_body
        + "\n"
        + github_release_note_data_body.replace(
            "## What's Changed", "#### Pull Requests:\n"
        ).replace("## New Contributors", "#### New Contributors:\n")
    )
else:
    new_release_note = release_body

logging.info("[implant] Updating the release")
requests.patch(
    "https://api.github.com/repos/OpenBAS-Platform/implant/releases/"
    + str(release_data["id"]),
    headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + github_token,
        "X-GitHub-Api-Version": "2022-11-28",
    },
    json={"body": new_release_note},
)

closeRelease(
    "https://api.github.com/repos/OpenBAS-Platform/implant", new_version, github_token
)
logging.info("[implant] Release done!")
