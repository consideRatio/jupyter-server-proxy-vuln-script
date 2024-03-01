
"""
This script is designed to check for and conditionally patch GHSA-w3vc-fx9p-wp4v
in user servers started by a JupyterHub.

Script assumptions:
- its run before the jupyter server starts

Script adjustments:
- UPGRADE_IF_VULNERABLE
- ERROR_IF_VULNERABLE

Read more at https://github.com/jupyterhub/jupyter-server-proxy/security/advisories/GHSA-w3vc-fx9p-wp4v.
"""

import os
import shutil
import subprocess
import sys

# adjust these to meet vulnerability mitigation needs
UPGRADE_IF_VULNERABLE = True
ERROR_IF_VULNERABLE = True


def check_vuln():
    """
    Checks for the vulnerability by looking to see if __version__ is available,
    it is since 3.2.3 and 4.1.1 that and those are the first patched versions.
    """
    try:
        import jupyter_server_proxy

        return False if hasattr(jupyter_server_proxy, "__version__") else True
    except:
        return False


def get_version_specifier():
    """
    Returns a pip/conda version specifier for use with `--no-deps` meant to do
    as little as possible besides patching the vulnerability and remaining
    functional.
    """
    old = ["jupyter-server-proxy>=3.2.3,<4"]
    new = ["jupyter-server-proxy>=4.1.1,<5", "simpervisor>=1,<2"]
    
    # Until we have released 3.2.3 and 4.1.1, this helps us test things
    if os.environ.get("TEST"):
        old = ["jupyter-server-proxy>=3.2.2,<4"]
        new = ["jupyter-server-proxy>=4.1.0,<5", "simpervisor>=1,<2"]

    try:
        if sys.version_info.minor < 8:
            return old

        from importlib.metadata import version

        jsp_version = version("jupyter-server-proxy")
        if int(jsp_version.split(".")[0]) < 4:
            return old
    except:
        pass
    return new


def patch_vuln():
    """
    Attempts to patch the vulnerability by upgrading jupyter-server-proxy using
    pip, or alternatively conda/mamba and the conda-forge channel if pip isn't
    installed and conda/mamba is.
    """
    # attempt upgrade via pip, takes ~4 seconds
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "--version"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pip_available = proc.returncode == 0
    if os.environ.get("TEST_NO_PIP"):
       pip_available = False 
    if pip_available:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--no-deps"]
            + get_version_specifier()
        )
        if proc.returncode == 0:
            return True

    # attempt upgrade via mamba/conda, takes ~40 seconds
    conda_executable = shutil.which("mamba") or shutil.which("conda")
    if conda_executable:
        proc = subprocess.run(
            [
                conda_executable,
                "install",
                "--yes",
                "--no-deps",
                "--channel=conda-forge",
            ]
            + get_version_specifier()
        )
        if proc.returncode == 0:
            return True

    return False


def main():
    if check_vuln():
        warning_or_error = "ERROR" if ERROR_IF_VULNERABLE and not UPGRADE_IF_VULNERABLE else "WARNING"
        print(
            f"{warning_or_error}: jupyter-server-proxy __is vulnerable__ to GHSA-w3vc-fx9p-wp4v, see "
            "https://github.com/jupyterhub/jupyter-server-proxy/security/advisories/GHSA-w3vc-fx9p-wp4v.",
            flush=True,
        )
        if warning_or_error == "ERROR":
            sys.exit(1)
        
        if UPGRADE_IF_VULNERABLE:
            print(
                "INFO: Attempting to upgrade jupyter-server-proxy using pip or mamba/conda...",
                flush=True,
            )
            if patch_vuln():
                print(
                    "INFO: Attempt to upgrade jupyter-server-proxy succeeded!",
                    flush=True,
                )
            else:
                warning_or_error = "ERROR" if ERROR_IF_VULNERABLE else "WARNING"
                print(
                    f"{warning_or_error}: Attempt to upgrade jupyter-server-proxy failed!",
                    flush=True,
                )
                if warning_or_error == "ERROR":
                    sys.exit(1)

main()
