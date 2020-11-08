import struct
import socket

from mitmproxy.proxy.protocol import base
from mitmproxy.proxy.modes import TransparentProxy

class TunnelLayer(base.Layer):
  def __init__(self, ctx):
    super().__init__(ctx)

  def __call__(self):
    # Extract the original destination
    client = self.ctx.client_conn
    dst = client.rfile.read(6)

    if len(dst) == 6:
      raw_ip, port = struct.unpack_from("!4sH", dst)
      ip = socket.inet_ntop(socket.AF_INET, raw_ip)

      # Continue as a normal transparent proxy layer
      proxy = TransparentProxy(self.ctx)
      proxy.set_server((ip, port))
      layer = self.ctx.next_layer(proxy)

      try:
        layer()
      finally:
        if self.server_conn.connected():
          self.disconnect()
