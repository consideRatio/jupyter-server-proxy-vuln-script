### Impact

Thanks to a missing `@web.authenticated` [here](https://github.com/jupyterhub/jupyter-server-proxy/blob/9b624c4d9507176334b46a85d94a4aa3bcd29bed/jupyter_server_proxy/handlers.py#L433) (and maybe in other places), websocket proxying is not authenticated *at all*.

I *think* this means that anyone with a JupyterHub with any packages that depend on `jupyter-server-proxy` and provide a websocket endpoint are vulnerable to remote code execution.

### Reproduction

#### Setup application to proxy

We'll make a trivial tornado app, that has both websocket and regular HTTP endpoints

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

#### Setup a clean environment with `jupyter-server-proxy` & start a `jupyter server` instance

We don't need jupyterlab or anything else here, just `jupyter-server-proxy` would do.

```bash
python -m venv clean-env/
source clean-env/bin/activate
pip install jupyter-server-proxy
jupyter server
```

#### Test if HTTP requests require authentication

```bash
curl -L http://127.0.0.1:8888/proxy/9500/hi
```

This does *not* return the `Hi` response, as expected. Instead, you get the HTML response asking for a token.

This is secure as intended.

#### Test if websocket requests require authentication

Instead of curl, I use [websocat](https://github.com/vi/websocat) to test websockets. You can use any other tool you are familiar with too.

```bash
websocat ws://localhost:8888/proxy/9500/ws
```

At the terminal, type 'Just testing' and press Enter. You'll get `You said: Just testing` without any authentication required :(