#!python3
# Socks5/HTTP Proxy server for Pythonista by @nneonneo
# Pretty statistics view and IPv6 support added by @philrosenthal

import ipaddress
import logging
import socket
import threading

from lib.socks5_server import AsyncSocks5Handler
from lib.http_proxy_server import AsyncHTTPProxyHandler
from lib.proxy_server import AsyncProxyServer
from lib.status import StatusMonitor

logging.basicConfig(level=logging.ERROR)

## Configuration
"""
Typical modes of operation:
- If you have a VPN turned on and want to send traffic via the VPN, set USE_PHONE_VPN = True, USE_SYSTEM_DNS = True.
  Otherwise, set USE_PHONE_VPN = False and USE_SYSTEM_DNS = False.
- If you are using tethering, connect all clients to the hotspot and set PROXY_HOST = "172.20.10.1".
- If you are connecting this phone and clients to some other WiFi network, set PROXY_HOST to this phone's address
  on that WiFi network and set USE_SYSTEM_DNS = False.

IPv6 hotspot clients:
- The server now listens on both IPv4 (0.0.0.0) and IPv6 (::) simultaneously (dual-stack).
- On a hotspot client, configure the proxy using the phone's IPv6 link-local address, e.g.:
    export https_proxy="http://[fe80::1%eth0]:9877"
    export http_proxy="http://[fe80::1%eth0]:9877"
    export ALL_PROXY="socks5://[fe80::1%eth0]:9876"
  where fe80::1 is the phone's link-local address and eth0 is the client's hotspot interface name.
- Alternatively, use the phone's hotspot IPv6 address (e.g. fd00::/8 prefix) shown by `ip addr` on the client:
    export ALL_PROXY="socks5://[fd12:3456:789a::1]:9876"
- On macOS/iOS clients, set the SOCKS proxy host to the bracketed IPv6 address in System Settings > Network > Proxies.
- PROXY_HOST below is used only to print the suggested address in the startup log and to generate the WPAD/PAC URL;
  it does not affect which address the server listens on. Set it to whichever address (IPv4 or IPv6) your clients
  will use to reach this proxy.
"""

# IP over which the proxy will be available (default: iOS tethering IPv4; set to the phone's WiFi or hotspot address,
# including an IPv6 address in brackets e.g. "[fe80::1]", if clients will connect over IPv6)
PROXY_HOST = "172.20.10.1"
# IP over which the proxy will attempt to connect to the Internet (will be autodetected from available networks)
CONNECT_HOST_IPV4 = "0.0.0.0"
CONNECT_HOST_IPV6 = None
# Time out connections after being idle for this long (in seconds)
IDLE_TIMEOUT = 1800
# Hosts to listen on - dual-stack: both IPv6 (::) and IPv4 (0.0.0.0)
LISTEN_HOSTS = ("::", "0.0.0.0")
# Port numbers to listen on
SOCKS_PORT = 9876 # SOCKS5 server
HTTP_PORT = 9877 # HTTP Proxy server
WPAD_PORT = 8088 # WPAD proxy autodiscovery server

USE_PHONE_VPN = True
# VPNs tend to ship their own DNS resolvers; since iOS will send all traffic
# via the VPN by default, we can trust the system DNS if using the phone VPN.
USE_SYSTEM_DNS = USE_PHONE_VPN
CUSTOM_RESOLVERS = []
# The proxy is unauthenticated, so by default it refuses to connect to
# private/loopback/link-local/carrier-internal destinations — otherwise any
# client could use it to reach your hotspot LAN or the carrier's network.
# Set to True only if you deliberately want to proxy into private ranges.
ALLOW_PRIVATE_DESTINATIONS = False

## End of configuration

# Try to keep the screen from turning off (iOS)
try:
    import console
    from objc_util import on_main_thread

    on_main_thread(console.set_idle_timer_disabled)(True)
except ImportError:
    pass


def is_globally_routable(ipv6_address):
    non_routable_networks = [
        "ff00::/8",  # Multicast address range
        "fe80::/10",  # Link-local address range
        "fc00::/7",  # Unique local address range
        "::/8",  # Unspecified address range
        "2001:db8::/32",  # Documentation address range
        "2001::/32",  # Teredo address range
        "2002::/16",  # 6to4 address range
        "ff02::/16",  # Link-local multicast address range
    ]
    for network in non_routable_networks:
        if ipaddress.ip_address(ipv6_address) in ipaddress.ip_network(network):
            return False
    return True


DEFAULT_RESOLVERS = [
    "1.0.0.1",
    "1.1.1.1",
    "8.8.8.8",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2001:4860:4860::8844",
]

if USE_SYSTEM_DNS:
    resolver = None
else:
    try:
        # TODO: configurable DNS (or find a way to use the cell network's own DNS)
        from dns import asyncresolver

        resolver = asyncresolver.Resolver(configure=False)
        resolver.nameservers += CUSTOM_RESOLVERS or DEFAULT_RESOLVERS
    except ImportError:
        # pip install dnspython
        print("Warning: dnspython not available; falling back to system DNS")
        resolver = None

try:
    # We want the WiFi/hotspot address so that clients know what IP to use.
    # We want the non-WiFi (cellular/VPN) address so that we can force network
    # traffic to go over that network. This allows the proxy to correctly
    # forward traffic to the cell network even when the WiFi network is
    # internet-enabled but limited (e.g. firewalled).

    from collections import defaultdict

    from lib import ifaddrs

    # Lines appended to these sections are joined into the startup banner.
    outbound_lines = []   # how outbound connections are made
    client_lines = []     # what address/port clients should use
    warning_lines = []    # non-fatal issues worth highlighting
    # All non-loopback addresses available for client connections, collected
    # as (iface_name, address_family, address_string) tuples.
    all_listen_addrs: list[tuple[str, int, str]] = []

    interfaces = ifaddrs.get_interfaces()
    iftypes = defaultdict(list)

    for iface in interfaces:
        if not iface.addr:
            continue
        if iface.name.startswith("lo"):
            continue
        if iface.name.startswith("en"):
            iftypes["en"].append(iface)
        elif iface.name.startswith("bridge"):
            iftypes["bridge"].append(iface)
        elif iface.name.startswith("utun"):
            iftypes["vpn"].append(iface)
        elif iface.name.startswith("pdp_ip"):
            iftypes["cell"].append(iface)
        # Ignore other iOS-internal interfaces (awdl, llw, ipsec, etc.)
        # Collect all IPv4 and IPv6 addresses across every non-loopback interface.
        if iface.addr.family in (socket.AF_INET, socket.AF_INET6) and iface.addr.address:
            all_listen_addrs.append((iface.name, iface.addr.family, iface.addr.address))

    # Sort cellular interfaces so pdp_ip0 is preferred over pdp_ip1, pdp_ip2, etc.
    iftypes["cell"].sort(key=lambda iface: iface.name)

    if iftypes["vpn"] and USE_PHONE_VPN:
        outbound_lines.append("VPN routing enabled (USE_PHONE_VPN=True)")
        new_ifaces = []
        new_ifaces.extend(iftypes["vpn"])
        new_ifaces.extend(iftypes["cell"])
        iftypes["cell"] = new_ifaces

    # Determine the address clients should use to reach this proxy (PROXY_HOST).
    if iftypes["bridge"]:
        iface = next(
            (
                iface
                for iface in iftypes["bridge"]
                if iface.addr.family == socket.AF_INET
            ),
            None,
        )
        if iface:
            PROXY_HOST = iface.addr.address
            client_lines.append(
                "Client network : hotspot interface %s  →  %s" % (iface.name, iface.addr.address)
            )
    elif iftypes["en"]:
        iface = next(
            (iface for iface in iftypes["en"] if iface.addr.family == socket.AF_INET),
            None,
        )
        if iface:
            PROXY_HOST = iface.addr.address
            client_lines.append(
                "Client network : WiFi interface %s  →  %s" % (iface.name, iface.addr.address)
            )
    else:
        warning_lines.append(
            "WARNING: Could not detect WiFi/hotspot address; using configured PROXY_HOST=%s" % PROXY_HOST
        )

    # Determine outbound interfaces (cellular / VPN).
    if iftypes["cell"]:
        iface_ipv4 = next(
            (iface for iface in iftypes["cell"] if iface.addr.family == socket.AF_INET),
            None,
        )
        iface_ipv6 = None

        is_vpn = iface_ipv4 and iface_ipv4.name.startswith("utun")

        if iface_ipv4:
            CONNECT_HOST_IPV4 = iface_ipv4.addr.address
            outbound_lines.append(
                "Outbound IPv4   : interface %s  →  %s"
                % (iface_ipv4.name, iface_ipv4.addr.address)
            )

            # Find globally-routable IPv6 address on the same interface.
            iface_ipv6_list = [
                iface
                for iface in iftypes["cell"]
                if iface.addr.family == socket.AF_INET6
                and iface.addr.address
                and (is_globally_routable(iface.addr.address) if not is_vpn else True)
                and iface.name == iface_ipv4.name
            ]
            # Prefer the last address (temporary/privacy address for reduced tracking).
            iface_ipv6 = iface_ipv6_list[-1] if iface_ipv6_list else None

        if iface_ipv6 is None and not is_vpn:
            # Fall back to any globally-routable IPv6 address on any interface.
            iface_ipv6_list = [
                iface
                for iface in iftypes["cell"]
                if iface.addr.family == socket.AF_INET6
                and iface.addr.address
                and is_globally_routable(iface.addr.address)
            ]
            iface_ipv6 = iface_ipv6_list[-1] if iface_ipv6_list else None

        if iface_ipv6:
            # Test IPv6 connectivity before committing to it.
            try:
                test_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                test_socket.settimeout(5)
                test_socket.bind((iface_ipv6.addr.address, 0))
                test_socket.connect(("2606:4700:4700::1111", 80))
                test_socket.close()
                CONNECT_HOST_IPV6 = iface_ipv6.addr.address
                outbound_lines.append(
                    "Outbound IPv6   : interface %s  →  %s  (connectivity OK)"
                    % (iface_ipv6.name, iface_ipv6.addr.address)
                )
            except Exception as e:
                CONNECT_HOST_IPV6 = None
                outbound_lines.append(
                    "Outbound IPv6   : interface %s  →  %s  (connectivity FAILED: %s)"
                    % (iface_ipv6.name, iface_ipv6.addr.address, e)
                )
            finally:
                test_socket.close()
        else:
            outbound_lines.append("Outbound IPv6   : not available")

    initial_output = ""
except Exception as e:
    logging.error("Address detection failed: %s: %s", (type(e).__name__, e))
    import traceback

    traceback.print_exc()

    interfaces = None
    outbound_lines = []
    client_lines = []
    warning_lines = []
    all_listen_addrs = []
    initial_output = ""


def create_wpad_server(hhost, hport, phost, pport):
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class HTTPHandler(BaseHTTPRequestHandler):
        def do_HEAD(s):
            s.send_response(200)
            s.send_header("Content-type", "application/x-ns-proxy-autoconfig")
            s.end_headers()

        def do_GET(s):
            s.send_response(200)
            s.send_header("Content-type", "application/x-ns-proxy-autoconfig")
            s.end_headers()
            s.wfile.write(
                (
                    """
function FindProxyForURL(url, host)
{
   if (isInNet(host, "192.168.0.0", "255.255.0.0")) {
      return "DIRECT";
   } else if (isInNet(host, "172.16.0.0", "255.240.0.0")) {
      return "DIRECT";
   } else if (isInNet(host, "10.0.0.0", "255.0.0.0")) {
      return "DIRECT";
   } else {
      return "SOCKS5 %s:%d; SOCKS %s:%d";
   }
}
"""
                    % (phost, pport, phost, pport)
                )
                .lstrip()
                .encode()
            )

    HTTPServer.allow_reuse_address = True
    server = HTTPServer((hhost, hport), HTTPHandler)
    return server


def run_wpad_server(server):
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    import asyncio

    wpad_server = create_wpad_server("0.0.0.0", WPAD_PORT, PROXY_HOST, SOCKS_PORT)

    # ── Listening addresses ──────────────────────────────────────────────────
    listen_section = [
        "┌─ Listening (dual-stack) ──────────────────────────────────────────",
        "│  IPv4  0.0.0.0       SOCKS5 port %d  │  HTTP port %d  │  WPAD port %d" % (SOCKS_PORT, HTTP_PORT, WPAD_PORT),
        "│  IPv6  [::]          SOCKS5 port %d  │  HTTP port %d" % (SOCKS_PORT, HTTP_PORT),
        "└───────────────────────────────────────────────────────────────────",
    ]

    # ── Outbound (how this device reaches the Internet) ──────────────────────
    outbound_section = ["┌─ Outbound (this device → Internet) ───────────────────────────────"]
    for line in (outbound_lines or ["│  (detection skipped)"]):
        outbound_section.append("│  " + line)
    outbound_section.append("└───────────────────────────────────────────────────────────────────")

    # ── Client setup (how remote clients reach this proxy) ───────────────────
    client_section = ["┌─ Client setup ────────────────────────────────────────────────────"]
    for line in client_lines:
        client_section.append("│  " + line)

    # Helper: format an address for use in a URL (IPv6 needs brackets).
    def fmt_addr(af, addr):
        return "[%s]" % addr if af == socket.AF_INET6 else addr

    # Deduplicate while preserving order.
    seen_addrs: set[tuple[int, str]] = set()
    unique_listen_addrs: list[tuple[str, int, str]] = []
    for iface_name, af, addr in all_listen_addrs:
        key = (af, addr)
        if key not in seen_addrs:
            seen_addrs.add(key)
            unique_listen_addrs.append((iface_name, af, addr))

    if unique_listen_addrs:
        client_section.append("│")
        client_section.append("│  Shell env examples — pick the address reachable from your client:")
        for iface_name, af, addr in unique_listen_addrs:
            proto = "IPv4" if af == socket.AF_INET else "IPv6"
            host = fmt_addr(af, addr)
            client_section.append("│")
            client_section.append("│  # %s  %s  (%s)" % (proto, addr, iface_name))
            client_section.append("│    export ALL_PROXY='socks5://%s:%d'" % (host, SOCKS_PORT))
            client_section.append("│    export http_proxy='http://%s:%d'" % (host, HTTP_PORT))
            client_section.append("│    export https_proxy='http://%s:%d'" % (host, HTTP_PORT))
    else:
        # Fallback when ifaddrs is not available (non-iOS platforms).
        proxy_ipv4 = PROXY_HOST or "0.0.0.0"
        client_section.append("│")
        client_section.append("│  SOCKS5  (IPv4)  socks5://%s:%d" % (proxy_ipv4, SOCKS_PORT))
        client_section.append("│  HTTP    (IPv4)  http://%s:%d" % (proxy_ipv4, HTTP_PORT))
        client_section.append("│  PAC/WPAD        http://%s:%d/wpad.dat" % (proxy_ipv4, WPAD_PORT))
        if CONNECT_HOST_IPV6:
            proxy_ipv6 = "[%s]" % CONNECT_HOST_IPV6
            client_section.append("│")
            client_section.append("│    export ALL_PROXY='socks5://%s:%d'" % (proxy_ipv6, SOCKS_PORT))
            client_section.append("│    export http_proxy='http://%s:%d'" % (proxy_ipv6, HTTP_PORT))
            client_section.append("│    export https_proxy='http://%s:%d'" % (proxy_ipv6, HTTP_PORT))

    client_section.append("│")
    client_section.append("│  PAC/WPAD  http://%s:%d/wpad.dat" % (PROXY_HOST or "0.0.0.0", WPAD_PORT))
    client_section.append("└───────────────────────────────────────────────────────────────────")

    if warning_lines:
        warn_section = ["┌─ Warnings ────────────────────────────────────────────────────────"]
        for line in warning_lines:
            warn_section.append("│  " + line)
        warn_section.append("└───────────────────────────────────────────────────────────────────")
    else:
        warn_section = []

    initial_output = "\n".join(
        listen_section + [""] + outbound_section + [""] + client_section
        + ([""] + warn_section if warn_section else [])
        + [""]
    )

    stats = StatusMonitor(initial_output)
    logging.getLogger().addHandler(stats)

    thread = threading.Thread(target=run_wpad_server, args=(wpad_server,))
    thread.daemon = True
    thread.start()

    async def main():
        server = AsyncProxyServer(
            AsyncSocks5Handler,
            listen_hosts=LISTEN_HOSTS,
            listen_port=SOCKS_PORT,
            traffic_stats=stats,
            resolver=resolver,
            connect_host_ipv4=CONNECT_HOST_IPV4,
            connect_host_ipv6=CONNECT_HOST_IPV6,
            allow_private_destinations=ALLOW_PRIVATE_DESTINATIONS,
        )
        asyncio.create_task(server.run())

        server = AsyncProxyServer(
            AsyncHTTPProxyHandler,
            listen_hosts=LISTEN_HOSTS,
            listen_port=HTTP_PORT,
            traffic_stats=stats,
            resolver=resolver,
            connect_host_ipv4=CONNECT_HOST_IPV4,
            connect_host_ipv6=CONNECT_HOST_IPV6,
            allow_private_destinations=ALLOW_PRIVATE_DESTINATIONS,
        )
        asyncio.create_task(server.run())

        await stats.render_forever()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down.")
        wpad_server.shutdown()
