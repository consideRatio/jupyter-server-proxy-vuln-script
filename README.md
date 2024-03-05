## Summary

`jupyter-server-proxy` is used to expose ports local to a Jupyter server
listening to web traffic to the Jupyter server's _authenticated users_ by
proxying via web requests and/or websockets. The vulnerability is that
`jupyter-server-proxy` has failed to check if the user is authenticated when
proxying websockets.

## Impact

This vulnerability can lead to remote code execution, for if for example a VNC
server is running and accepting websockets next to the Jupyter server, like
enabled by [`jupyter-remote-desktop-proxy`].

[`jupyter-remote-desktop-proxy`]: https://github.com/jupyterhub/jupyter-remote-desktop-proxy

## Remediation

Upgrade `jupyter-server-proxy` to a patched version and restart any running
Jupyter server.

### For JupyterHub admins of [TLJH] installations

<details><summary>Expand to read more</summary>

To secure a tljh deployment's user servers, first check if
`jupyter-server-proxy` is installed in the user environment with a vulnerable
version. If it is, patch the vulnerability and consider terminating currently
running user servers.

[tljh]: https://tljh.jupyter.org

#### 1. Check for vulnerability

As an JupyterHub admin from a terminal in a started user server, you can do:

```bash
sudo -E python3 -c '
try:
    import jupyter_server_proxy
    is_vulnerable = not hasattr(jupyter_server_proxy, "__version__")
except:
    is_vulnerable = False
if is_vulnerable:
    print("WARNING: jupyter-server-proxy __is vulnerable__ to GHSA-w3vc-fx9p-wp4v, see https://github.com/jupyterhub/jupyter-server-proxy/security/advisories/GHSA-w3vc-fx9p-wp4v.")
else:
    print("INFO: not vulnerable to GHSA-w3vc-fx9p-wp4v")
'
```

Alternatively as a root user on the server where tljh is installed, you can do:

```bash
sudo PATH=/opt/tljh/user/bin:${PATH} python3 -c '
try:
    import jupyter_server_proxy
    is_vulnerable = not hasattr(jupyter_server_proxy, "__version__")
except:
    is_vulnerable = False
if is_vulnerable:
    print("WARNING: jupyter-server-proxy __is vulnerable__ to GHSA-w3vc-fx9p-wp4v, see https://github.com/jupyterhub/jupyter-server-proxy/security/advisories/GHSA-w3vc-fx9p-wp4v.")
else:
    print("INFO: not vulnerable to GHSA-w3vc-fx9p-wp4v")
'
```

#### 2. Patch detected vulnerability

As an JupyterHub admin from a terminal in a started user server, you can do:

```bash
sudo -E pip install "jupyter-server-proxy>=3.2.3,!=4.0.0,!=4.1.0"
```

Alternatively as a root user on the server where tljh is installed, you can do:

```bash
sudo PATH=/opt/tljh/user/bin:${PATH} pip install "jupyter-server-proxy>=3.2.3,!=4.0.0,!=4.1.0"
```

#### 3. Consider terminating currently running user servers

User servers that started before the patch was applied are still vulnerable. To
ensure they aren't vulnerable any more you could forcefully terminate their
servers via the JupyterHub web interface at `https://<your domain>/hub/admin`.

</details>

### For JupyterHub admins of [Z2JH] installations

<details><summary>Expand to read more</summary>

To secure your z2jh deployment's user servers, first consider if one or more
user environments is or may be vulnerable, then ensure new user servers' aren't
started with the vulnerability, and finally consider terminating currently
running user servers.

[z2jh]: https://z2jh.jupyter.org

#### 1. Check for vulnerabilities

Consider all docker images that user servers' environment may be based on. If
your deployment expose a fixed set of images, you may be able to update them to
non-vulnerable versions.

To check if an individual docker image is vulnerable, use a command like:

```bash
CHECK_IMAGE=jupyter/base-notebook:2023-10-20
docker run --rm $CHECK_IMAGE python3 -c '
try:
    import jupyter_server_proxy
    is_vulnerable = not hasattr(jupyter_server_proxy, "__version__")
except:
    is_vulnerable = False
if is_vulnerable:
    print("WARNING: jupyter-server-proxy __is vulnerable__ to GHSA-w3vc-fx9p-wp4v, see https://github.com/jupyterhub/jupyter-server-proxy/security/advisories/GHSA-w3vc-fx9p-wp4v.")
else:
    print("INFO: not vulnerable to GHSA-w3vc-fx9p-wp4v")
'
```

Note that if you reference an image with a mutable tag, such as
`quay.io/jupyter/pangeo-notebook:master`, you should ensure a new version is
used by configuring the image pull policy so that an older vulnerable version
isn't kept being used because it was already available on a Kubernetes node.

```yaml
singleuser:
  image:
    name: quay.io/jupyter/pangeo-notebook
    tag: master
    # pullPolicy (a.k.a. imagePullPolicy in k8s specification) should be
    # declared to Always if you make use of mutable tags
    pullPolicy: Always
```

#### 2. Patch vulnerabilities dynamically

If your z2jh deployment still may start vulnerable images for users, you could
mount a script that checks and patches the vulnerability before the jupyter
server starts.

Below is JupyterHub Helm chart configuration that relies on
[`singleuser.extraFiles`] and [`singleuser.cmd`] to mount a script we use as an
entrypoint to dynamically check and patch the vulnerability before jupyter
server is started.

Unless you change it, the script will attempt to upgrade `jupyter-server-proxy`
to a non-vulnerable version if needed, and error if it needs to and fails. You
can adjust this behavior by adjusting the constants `UPGRADE_IF_VULNERABLE` and
`ERROR_IF_VULNERABLE` inside the script.

[`singleuser.extraFiles`]: https://z2jh.jupyter.org/en/stable/resources/reference.html#singleuser-extrafiles
[`singleuser.cmd`]: https://z2jh.jupyter.org/en/stable/resources/reference.html#singleuser-cmd

```yaml
singleuser:
  cmd:
    - /mnt/ghsa-w3vc-fx9p-wp4v/check-patch-run
    - jupyterhub-singleuser
  extraFiles:
    ghsa-w3vc-fx9p-wp4v-check-patch-run:
      mountPath: /mnt/ghsa-w3vc-fx9p-wp4v/check-patch-run
      mode: 0755
      stringData: |
        #!/usr/bin/env python3
        """
        This script is designed to check for and conditionally patch GHSA-w3vc-fx9p-wp4v
        in user servers started by a JupyterHub. The script will execute any command
        passed via arguments if provided, allowing it to wrap a user server startup call
        to `jupyterhub-singleuser` for example.

        Script adjustments:
        - UPGRADE_IF_VULNERABLE
        - ERROR_IF_VULNERABLE

        Script patching assumptions:
        - script is run before the jupyter server starts
        - pip is available
        - pip has sufficient filesystem permissions to upgrade jupyter-server-proxy

        Read more at https://github.com/jupyterhub/jupyter-server-proxy/security/advisories/GHSA-w3vc-fx9p-wp4v.
        """

        import os
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
            Returns a pip version specifier for use with `--no-deps` meant to do as
            little as possible besides patching the vulnerability and remaining
            functional.
            """
            old = ["jupyter-server-proxy>=3.2.3,<4"]
            new = ["jupyter-server-proxy>=4.1.1,<5", "simpervisor>=1,<2"]

            try:
                if sys.version_info < (3, 8):
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
            pip.
            """
            # attempt upgrade via pip, takes ~4 seconds
            proc = subprocess.run(
                [sys.executable, "-m", "pip", "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            pip_available = proc.returncode == 0
            if pip_available:
                proc = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--no-deps"]
                    + get_version_specifier()
                )
                if proc.returncode == 0:
                    return True


        def main():
            if check_vuln():
                warning_or_error = (
                    "ERROR" if ERROR_IF_VULNERABLE and not UPGRADE_IF_VULNERABLE else "WARNING"
                )
                print(
                    f"{warning_or_error}: jupyter-server-proxy __is vulnerable__ to GHSA-w3vc-fx9p-wp4v, see "
                    "https://github.com/jupyterhub/jupyter-server-proxy/security/advisories/GHSA-w3vc-fx9p-wp4v.",
                    flush=True,
                )
                if warning_or_error == "ERROR":
                    sys.exit(1)

                if UPGRADE_IF_VULNERABLE:
                    print(
                        "INFO: Attempting to upgrade jupyter-server-proxy using pip...",
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

            if len(sys.argv) >= 2:
                print("INFO: Executing provided command", flush=True)
                os.execvp(sys.argv[1], sys.argv[1:])
            else:
                print("INFO: No command to execute provided", flush=True)


        main()
```

#### 3. Consider terminating currently running user servers

User servers that started before the patch was applied are still vulnerable. To
ensure they aren't vulnerable any more you could forcefully terminate their
servers via the JupyterHub web interface at `https://<your domain>/hub/admin`.

</details>

## Reproduction

<details><summary>Expand to read more</summary>

### Setup application to proxy

Make a trivial tornado app that has both websocket and regular HTTP endpoints.

```python
from tornado import websocket, web, ioloop

class EchoWebSocket(websocket.WebSocketHandler):
    def open(self):
        print("WebSocket opened")

    def on_message(self, message):
        self.write_message(u"You said: " + message)

    def on_close(self):
        print("WebSocket closed")

class HiHandler(web.RequestHandler):
    def get(self):
        self.write("Hi")

app = web.Application([
    (r'/ws', EchoWebSocket),
    (r'/hi', HiHandler)
])

if __name__ == '__main__':
    app.listen(9500)
    ioloop.IOLoop.instance().start()
```

### Setup a clean environment with `jupyter-server-proxy` and start a `jupyter server` instance

We don't need jupyterlab or anything else here, just `jupyter-server-proxy` would do.

```bash
python -m venv clean-env/
source clean-env/bin/activate
pip install jupyter-server-proxy
jupyter server
```

### Verify HTTP requests require authentication

```bash
curl -L http://127.0.0.1:8888/proxy/9500/hi
```

This does *not* return the `Hi` response, as expected. Instead, you get the HTML response asking for a token.

This is secure as intended.

### Verify websocket requests doesn't authentication

The example makes use of [websocat](https://github.com/vi/websocat) to test
websockets. You can use any other tool you are familiar with too.

```bash
websocat ws://localhost:8888/proxy/9500/ws
```

At the terminal, type 'Just testing' and press Enter. You'll get `You said: Just
testing` without any authentication required.

</details>
