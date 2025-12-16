import os
import argparse

try:
    import toml
except ImportError:
    raise Exception("❌pip install toml")


parser = argparse.ArgumentParser()

# Add a new argument to the parser for major version

parser.add_argument("--major", action="store_true")

# Add a new argument to the parser for minor version

parser.add_argument("--minor", action="store_true")

# Add a new argument to the parser for patch version

parser.add_argument("--patch", action="store_true")

args = parser.parse_args()

# Read version from pyproject.toml

with open("pyproject.toml") as f:
    config = toml.load(f)

version = config["project"]["version"]

# Update major version

if args.major:
    version = version[1:].split(".")
    major = str(int(version[0]) + 1)
    version[0] = "v{0}".format(major)
    version[1] = "0"
    version[2] = "0"

    version = ".".join(version)

# Update minor version

if args.minor:
    version = version.split(".")

    version[1] = str(int(version[1]) + 1)
    version[2] = "0"

    version = ".".join(version)

# Update patch version

if args.patch:
    version = version.split(".")

    version[2] = str(int(version[2]) + 1)

    version = ".".join(version)

# Create a new tag with the new version

# Check if there are any changes in the repository

if os.system("git diff-index --quiet HEAD --") != 0:
    print(
        "There are changes in the repository. Please commit them before deploying."
    )
    exit(1)

# Run tests

if os.system("pytest") != 0:
    print("Tests failed. Please fix them before deploying.")
    exit(1)

# Write new version to pyproject.toml

version = version

config["project"]["version"] = version

with open("pyproject.toml", "w") as f:
    toml.dump(config, f)

# Commit changes and create a new tag

os.system("git add pyproject.toml")

os.system("git commit -m 'Bump version to {0}'".format(version))

os.system("git tag -a {0} -m 'Version {0}'".format(version))

os.system("git push origin tag {0}".format(version))

os.system("git push")
