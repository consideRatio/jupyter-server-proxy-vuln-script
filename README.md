# TODO

- Clarify that the vulnerability is only websocket related.
- Be more explicit on how to check for the vulnerability for tljh / z2jh user
  environments.
- List currently running servers?
- Terminate currently running servers?

# Securing JupyterHub deployments

1. Check if the deployment is vulnerable
2. Ensure user environment is/gets patched
3. Make current users restart

## The littlest JupyterHub deployments (tljh)

To secure a tljh deployment's user servers, first upgrade `jupyter-server-proxy`
in the user environment and then ask currently running users to restart their
servers or forcefully terminate them.

As an JupyterHub admin from a user server you can do:

```bash
sudo -E pip install "jupyter-server-proxy>=3.2.3,!=4.0.0,!=4.1.0"
```

Alternatively as a root user on server where tljh is installed, you can do:

```bash
export PATH=/opt/tljh/user/bin:${PATH}
sudo PATH=${PATH} pip install "jupyter-server-proxy>=3.2.3,!=4.0.0,!=4.1.0"
```

## JupyterHub Helm chart deployments (z2jh)

To secure a z2jh deployment's user servers, we must ensure
`jupyter-server-proxy` is up to date in the user environments, and then ask
currently running users to restart their servers or forcefully terminate them.

Below is JupyterHub helm chart configuration that relies on
[`singleuser.extraFiles`] and [`singleuser.cmd`]. The idea behind it is to
instead of starting `jupyterhub-singleuser` directly, to start a Python script
that upgrades `jupyter-server-proxy` if needed before transitioning to starting
`jupyterhub-singleuser`.

[`singleuser.extraFiles`]: https://z2jh.jupyter.org/en/stable/resources/reference.html#singleuser-extrafiles
[`singleuser.cmd`]: https://z2jh.jupyter.org/en/stable/resources/reference.html#singleuser-cmd

```yaml
singleuser:
  extraFiles:
    checkVulnScript:
      mountPath: /injected/check-vuln-then-jupyterhub-singleuser.py
      stringData: |
        """
        This script is designed to check for and conditionally patch GHSA-w3vc-fx9p-wp4v
        in user servers started by a JupyterHub.

        Script assumptions:
        - its started before the jupyter server
        - it responsible for starting "jupyterhub-singleuser"

        Script adjustments:
        - upgrade_if_vulnerable can be used to opt out of attempting to patch the vulnerability
        - error_if_vulnerable can be used to opt out of erroring vulnerable user servers

        Read more at https://github.com/jupyterhub/jupyter-server-proxy/security/advisories/GHSA-w3vc-fx9p-wp4v.
        """

        import os
        import shutil
        import subprocess
        import sys

        # adjust these to meet vulnerability mitigation needs
        upgrade_if_vulnerable = True
        error_if_vulnerable = True

        install_specifier = "jupyter-server-proxy>=3.2.3,!=4.0.0,!=4.1.0"


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


        def patch_vuln():
            """
            Attempts to patch the vulnerability by upgrading jupyter-server-proxy using
            pip, or alternatively conda/mamba and the conda-forge channel if pip isn't
            installed and conda/mamba is.
            """
            # attempt upgrade via pip
            proc = subprocess.run(
                [sys.executable, "-m", "pip", "--help"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            pip_available = proc.returncode == 0
            if pip_available:
                proc = subprocess.run(
                    [sys.executable, "-m", "pip", "install", install_specifier]
                )
                if proc.returncode == 0:
                    return True

            # attempt upgrade via mamba/conda
            conda_executable = ""
            proc = subprocess.run(
                [sys.executable, "-m", "mamba", "--help"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if proc.returncode == 0:
                conda_executable = "mamba"
            else:
                proc = subprocess.run(
                    [sys.executable, "-m", "conda", "--help"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if proc.returncode == 0:
                    conda_executable = "conda"
            if conda_executable:
                proc = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        conda_executable,
                        "install",
                        "--yes",
                        "--channel=conda-forge",
                        install_specifier,
                    ]
                )
                if proc.returncode == 0:
                    return True

            return False


        def main():
            if check_vuln():
                print(
                    "WARNING: jupyter-server-proxy __is vulnerable__ to GHSA-w3vc-fx9p-wp4v, see https://github.com/jupyterhub/jupyter-server-proxy/security/advisories/GHSA-w3vc-fx9p-wp4v.",
                    flush=True,
                )
                if error_if_vulnerable and not upgrade_if_vulnerable:
                    sys.exit(1)

                print(
                    "INFO: Attempting to upgrade jupyter-server-proxy using pip or mamba/conda...",
                    flush=True,
                )
                if patch_vuln():
                    print(
                        "INFO: Attempt to upgrade jupyter-server-proxy succeeded!", flush=True
                    )
                else:
                    warning_or_error = "ERROR" if error_if_vulnerable else "WARNING"
                    print(
                        f"{warning_or_error}: Attempt to upgrade jupyter-server-proxy failed!",
                        flush=True,
                    )
                    if error_if_vulnerable:
                        sys.exit(1)

            jhs_path = shutil.which("jupyterhub-singleuser")
            if not jhs_path:
                print("ERROR: jupyterhub-singleuser not found on path", flush=True)
                sys.exit(1)
            os.execv(sys.executable, [sys.executable, jhs_path])


        main()
```
