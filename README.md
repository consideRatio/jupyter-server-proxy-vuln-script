JupyterHub 3, released 2022-09-09


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
  cmd:
    - /mnt/ghsa-w3vc-fx9p-wp4v/check-patch-run
    - jupyterhub-singleuser
  extraFiles:
    ghsa-w3vc-fx9p-wp4v-check-patch-run:
      mountPath: /mnt/ghsa-w3vc-fx9p-wp4v/check-patch-run
      mode: 0755
      stringData: |
        <copied from check-patch-run>
```
