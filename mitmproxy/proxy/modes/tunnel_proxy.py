from mitmproxy import exceptions
from mitmproxy import platform
from mitmproxy.proxy import protocol


class TunnelProxy(protocol.Layer, protocol.ServerConnectionMixin):

    def __init__(self, ctx):
        super().__init__(ctx)

    def __call__(self):
        layer = self.ctx.next_layer(self)
        try:
            layer()
        finally:
            if self.server_conn.connected():
                self.disconnect()
