"""Path-based WebSocket bridge for Cloudflare Tunnel deployments.

Cloudflare Tunnel can only route the public hostname to one origin unless the
remote ingress config has a more specific `/ws*` rule. This middleware lets the
Flask/Gunicorn origin on port 2500 accept public `wss://host/ws` upgrades and
bridge them to OpenAlgo's local market-data WebSocket proxy on 127.0.0.1:8765.
"""

import os

from utils.logging import get_logger

logger = get_logger(__name__)


class WebSocketPathProxyMiddleware:
    """WSGI middleware that proxies `/ws` WebSocket upgrades to local port 8765.

    The middleware is intentionally narrow: only `/ws` and `/ws/` with
    `Upgrade: websocket` are intercepted. Everything else, including Socket.IO
    at `/socket.io/`, is passed through unchanged to Flask/Flask-SocketIO.
    """

    def __init__(self, app, target_url=None):
        self.app = app
        port = os.getenv("WEBSOCKET_PORT", "8765").strip().strip("'\"") or "8765"
        self.target_url = target_url or f"ws://127.0.0.1:{port}"

        # Import lazily here so normal imports/tests do not require eventlet's
        # websocket stack unless the production WSGI app is being built.
        from eventlet.websocket import WebSocketWSGI

        self._ws_app = WebSocketWSGI(self._handle_ws)

    def __call__(self, environ, start_response):
        path = (environ.get("PATH_INFO") or "").rstrip("/") or "/"
        if path == "/ws":
            upgrade = (environ.get("HTTP_UPGRADE") or "").lower()
            if upgrade == "websocket":
                return self._ws_app(environ, start_response)

            # Be explicit for plain HTTP GETs so diagnostics don't get the React
            # app's index.html and falsely appear as HTTP 200.
            start_response(
                "426 Upgrade Required",
                [
                    ("Content-Type", "text/plain; charset=utf-8"),
                    ("Connection", "Upgrade"),
                    ("Upgrade", "websocket"),
                ],
            )
            return [b"OpenAlgo market-data WebSocket endpoint. Use WebSocket upgrade.\n"]

        return self.app(environ, start_response)

    def _handle_ws(self, downstream):
        import eventlet
        import websocket

        upstream = None
        done = eventlet.event.Event()

        def close_once():
            if not done.ready():
                try:
                    done.send(True)
                except Exception:
                    pass
            # Do not close the downstream Eventlet WebSocket explicitly here.
            # WebSocketWSGI owns that socket and will close it when this handler
            # returns; double-closing it makes Eventlet log noisy
            # "socket shutdown error: [Errno 9] Bad file descriptor" messages.
            if upstream is not None:
                try:
                    upstream.close()
                except Exception:
                    pass

        try:
            upstream = websocket.create_connection(
                self.target_url,
                timeout=10,
                enable_multithread=True,
            )
        except Exception as exc:
            logger.error("/ws bridge failed to connect to %s: %s", self.target_url, exc)
            close_once()
            return

        def downstream_to_upstream():
            try:
                while True:
                    msg = downstream.wait()
                    if msg is None:
                        break
                    if isinstance(msg, bytes):
                        upstream.send_binary(msg)
                    else:
                        upstream.send(msg)
            except Exception:
                pass
            finally:
                close_once()

        def upstream_to_downstream():
            try:
                while True:
                    msg = upstream.recv()
                    downstream.send(msg)
            except Exception:
                pass
            finally:
                close_once()

        eventlet.spawn_n(downstream_to_upstream)
        eventlet.spawn_n(upstream_to_downstream)
        done.wait()


def install_ws_path_proxy(app):
    """Install the `/ws` bridge as the outermost WSGI middleware."""
    if getattr(app, "_openalgo_ws_path_proxy_installed", False):
        return app
    app.wsgi_app = WebSocketPathProxyMiddleware(app.wsgi_app)
    app._openalgo_ws_path_proxy_installed = True
    logger.info("Installed /ws WebSocket path bridge to local OpenAlgo WS proxy")
    return app
