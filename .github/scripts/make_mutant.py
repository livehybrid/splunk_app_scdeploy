#!/usr/bin/env python3
"""Build a deliberately broken copy of the packaged app for the SCTS self-test.

The mutant reverses the token gendeploytoken hands to the destination. Every
other behaviour is untouched, so on a correct set of checks exactly one goes
red: delivered_token_authenticates. Any other count means a check is blind or
over-broad. The version gets a `.mutant` suffix so the install read-back proves
the mutant, not the real build, is what ran.

usage: make_mutant.py <package.tar.gz> <version> <out.tar.gz>
"""
import json
import os
import sys
import tarfile
import tempfile

APP = "splunk_app_scdeploy"
SITE = '"token": tokenObj["token"],'
MUTATION = '"token": tokenObj["token"][::-1],'


def main(package: str, version: str, out: str) -> None:
    work = tempfile.mkdtemp()
    with tarfile.open(package) as tar:
        tar.extractall(work, filter="data")
    root = os.path.join(work, APP)
    path = os.path.join(root, "bin", "gendeploytoken.py")
    src = open(path).read()
    if src.count(SITE) != 1:
        sys.exit("mutation site not found exactly once in gendeploytoken.py")
    open(path, "w").write(src.replace(SITE, MUTATION))

    mutant_version = version + ".mutant"
    conf = os.path.join(root, "default", "app.conf")
    text = open(conf).read()
    new = text.replace("version = " + version, "version = " + mutant_version)
    if new == text:
        sys.exit("version {} not found in app.conf".format(version))
    open(conf, "w").write(new)
    manifest = os.path.join(root, "app.manifest")
    data = json.load(open(manifest))
    data["info"]["id"]["version"] = mutant_version
    json.dump(data, open(manifest, "w"), indent=2)

    with tarfile.open(out, "w:gz") as tar:
        tar.add(root, arcname=APP)
    print(mutant_version)


if __name__ == "__main__":
    main(*sys.argv[1:4])
