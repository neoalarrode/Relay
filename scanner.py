#!/usr/bin/env python3
"""
Movistar IPTV Scanner & Proxy

Complete IPTV application for Movistar Spain:
  - Discovers all channels from the Movistar DVB multicast network
  - Scans channels to detect which are unencrypted (TSC bit analysis)
  - Serves free channels as HTTP MPEG-TS streams (multicast-to-HTTP proxy)
  - Downloads and serves full EPG (XMLTV) for all channels
  - Periodic background rescanning with dynamic channel updates
  - SOCKS5 proxy and udpxy relay support

Usage:
    ./scanner.py --serve                            # Full service
    ./scanner.py --serve --daemon --interval 3600   # With periodic rescan
    ./scanner.py --serve --proxy socks5://h:p        # Via SOCKS5
"""

import argparse
import gzip
import http.server
import json
import logging
import logging.handlers
import os
import re
import signal
import socket
import struct
import sys
import time
import threading
import urllib.request
from collections import defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
from html import unescape
from xml.etree.ElementTree import fromstring

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

try:
    import socks
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False

__version__ = "2.0.0"

# ─── Constants ────────────────────────────────────────────────────────────────

TS_SYNC = 0x47
TS_SIZE = 188
IPTV_DNS = "172.26.23.3"
UA = "libcurl-agent/1.0 [IAL] WidgetManager Safari/538.1 CAP:803fd12a 1"

SI_PIDS = frozenset(range(0x20)) | {0x1FFF}

END_POINTS = (
    "http://portalnc.imagenio.telefonica.net:2001",
    "http://asiptvnc.imagenio.telefonica.net:2070",
    "http://reg360.imagenio.telefonica.net:2070",
)

DEMARCATIONS = {
    15: "Andalucia", 34: "Aragon", 13: "Asturias", 29: "Cantabria",
    1: "Catalunya", 38: "Castilla la Mancha", 4: "Castilla y Leon",
    6: "Comunidad Valenciana", 32: "Extremadura", 24: "Galicia",
    10: "Islas Baleares", 37: "Islas Canarias", 31: "La Rioja",
    19: "Madrid", 12: "Murcia", 35: "Navarra", 36: "Pais Vasco",
}

GENRE_MAP = {
    "1": "Movie / Drama", "01": "Cine", "02": "Deportes",
    "03": "Documentales", "04": "Infantil", "05": "Música",
    "06": "Otros", "07": "Programas", "08": "Series",
    "10": "Cine", "20": "Deportes", "30": "Documentales",
    "40": "Infantil", "50": "Música", "60": "Otros",
    "70": "Programas", "80": "Series",
}

log = logging.getLogger("movistar")


# ═══════════════════════════════════════════════════════════════════════════════
#  SOCKS5 Proxy Support
# ═══════════════════════════════════════════════════════════════════════════════

class ProxyConfig:
    def __init__(self, proxy_url=None):
        self.enabled = False
        self.host = self.port = self.username = self.password = None
        if proxy_url:
            self._parse(proxy_url)

    def _parse(self, url):
        url = re.sub(r"^socks5h?://", "", url)
        auth = None
        if "@" in url:
            auth, url = url.rsplit("@", 1)
        self.host, self.port = (url.rsplit(":", 1) + ["1080"])[:2]
        self.port = int(self.port)
        if auth:
            parts = auth.split(":", 1)
            self.username = parts[0]
            self.password = parts[1] if len(parts) > 1 else None
        self.enabled = True

    def get_opener(self):
        if not self.enabled:
            return urllib.request.build_opener()
        if not HAS_SOCKS:
            raise RuntimeError("PySocks required: pip install pysocks")
        from sockshandler import SocksiPyHandler
        return urllib.request.build_opener(
            SocksiPyHandler(socks.SOCKS5, self.host, self.port,
                            username=self.username, password=self.password))


# ═══════════════════════════════════════════════════════════════════════════════
#  Movistar Network / API
# ═══════════════════════════════════════════════════════════════════════════════

MOVISTAR_IPTV_DEFAULT = "192.168.2.5"


def detect_iptv_ip():
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
            s.settimeout(3)
            s.connect((IPTV_DNS, 53))
            return s.getsockname()[0]
    except OSError:
        pass
    log.warning("Auto-detect failed, using default IPTV IP: %s", MOVISTAR_IPTV_DEFAULT)
    return MOVISTAR_IPTV_DEFAULT


def http_get(url, proxy=None, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    opener = proxy.get_opener() if proxy and proxy.enabled else urllib.request.build_opener()
    resp = opener.open(req, timeout=timeout)
    return resp.read().decode("utf-8")


def api_call(endpoint, action, proxy=None):
    try:
        data = http_get(f"{endpoint}?action={action}", proxy)
        return json.loads(unescape(data)).get("resultData")
    except Exception as e:
        log.debug("API %s failed: %s", action, e)
        return None


def find_endpoint(proxy=None):
    for ep in END_POINTS:
        try:
            http_get(ep + "/appserver/mvtv.do?action=getClientProfile", proxy, timeout=5)
            return ep + "/appserver/mvtv.do"
        except Exception:
            continue
    return None


# ═══════════════════════════════════════════════════════════════════════════════
#  DVB Multicast Data Download
# ═══════════════════════════════════════════════════════════════════════════════

def multicast_join(addr, port, iptv_ip, timeout=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    sock.settimeout(timeout)
    try:
        sock.bind((addr, port))
    except OSError:
        sock.bind(("", port))
    mreq = struct.pack("4s4s", socket.inet_aton(addr), socket.inet_aton(iptv_ip))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    return sock, mreq


def parse_dvb_chunk(data):
    return {
        "end": struct.unpack("B", data[:1])[0],
        "filetype": struct.unpack("B", data[4:5])[0],
        "fileid": struct.unpack(">H", data[5:7])[0] & 0x0FFF,
        "data": data[12:].decode("latin1"),
    }


def download_dvb_xml(addr, port, iptv_ip, timeout=60):
    files = {}
    sock, mreq = multicast_join(addr, port, iptv_ip, timeout=5)
    deadline = time.time() + timeout
    last_file = None

    try:
        while time.time() < deadline:
            try:
                chunk = parse_dvb_chunk(sock.recv(65535))
                if chunk["end"]:
                    last_file = f"{chunk['filetype']}_{chunk['fileid']}"
                    break
            except (socket.timeout, struct.error):
                continue

        if not last_file:
            return files

        while time.time() < deadline:
            xmldata = ""
            chunk = {"end": False}
            try:
                while not chunk["end"]:
                    chunk = parse_dvb_chunk(sock.recv(65535))
                    xmldata += chunk["data"]
                key = f"{chunk['filetype']}_{chunk['fileid']}"
                files[key] = xmldata[:-4]
                if key == last_file:
                    break
            except (socket.timeout, struct.error):
                continue
    finally:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
        except OSError:
            pass
        sock.close()

    return files


def parse_channels_xml(xml_str):
    channels = {}
    ns = "urn:dvb:ipisdns:2006"
    try:
        root = fromstring(xml_str.replace("\n", " "))
        for svc in root.iter(f"{{{ns}}}SingleService"):
            try:
                ti = svc.find(f".//{{{ns}}}TextualIdentifier")
                ip = svc.find(f".//{{{ns}}}IPMulticastAddress")
                si = svc.find(f"{{{ns}}}ServiceInfo") or svc.find(f"{{{ns}}}SI")
                if ti is None or ip is None:
                    continue

                ch_id = int(ti.attrib.get("ServiceName", "0"))
                if ch_id == 0:
                    continue

                name = ""
                name_el = si.find(f"{{{ns}}}Name") if si is not None else None
                if name_el is not None and name_el.text:
                    try:
                        name = name_el.text.encode("latin1").decode("utf8").strip(" .*")
                    except (UnicodeDecodeError, UnicodeEncodeError):
                        name = name_el.text.strip(" .*")

                genre_parent = si.find(f"{{{ns}}}Genre") if si is not None else None
                genre_el = genre_parent.find(f"{{{ns}}}Name") if genre_parent is not None else None
                genre = ""
                if genre_el is not None and genre_el.text:
                    try:
                        genre = genre_el.text.encode("latin1").decode("utf8")
                    except (UnicodeDecodeError, UnicodeEncodeError):
                        genre = genre_el.text

                channels[ch_id] = {
                    "id": ch_id,
                    "address": ip.attrib["Address"],
                    "port": int(ip.attrib["Port"]),
                    "name": name or f"Channel {ch_id}",
                    "genre": genre,
                    "logo_uri": ti.attrib.get("logoURI", ""),
                }

                repl = si.find(f"{{{ns}}}ReplacementService") if si is not None else None
                if repl is not None:
                    repl_ti = repl.find(f"{{{ns}}}TextualIdentifier")
                    if repl_ti is not None:
                        channels[ch_id]["replacement"] = int(repl_ti.attrib.get("ServiceName", "0"))
            except (KeyError, ValueError, AttributeError):
                continue
    except Exception as e:
        log.error("Channel XML parse error: %s", e)
    return channels


def parse_packages_xml(xml_str):
    packages = {}
    ns = "urn:dvb:ipisdns:2006"
    try:
        root = fromstring(xml_str.replace("\n", " "))
        for pkg in root[0].iter(f"{{{ns}}}Package"):
            pname_el = pkg.find(f"{{{ns}}}PackageName")
            pname = pname_el.text if pname_el is not None else "Unknown"
            services = {}
            for svc in pkg:
                if svc.tag == f"{{{ns}}}PackageName":
                    continue
                ti = svc.find(f"{{{ns}}}TextualIdentifier")
                ln = svc.find(f"{{{ns}}}LogicalChannelNumber")
                if ti is not None and ln is not None:
                    services[ti.attrib.get("ServiceName", "0")] = ln.text
            if services:
                packages[pname] = {"services": services}
    except Exception as e:
        log.debug("Package XML parse error: %s", e)
    return packages


def parse_segments_xml(xml_str):
    segments = {}
    ns = "urn:dvb:ipisdns:2006"
    try:
        root = fromstring(xml_str.replace("\n", " "))
        for seg in root[0][1][1].iter(f"{{{ns}}}DVBBINSTP"):
            source = seg.attrib["Source"]
            segments[source] = {
                "Source": source,
                "Port": int(seg.attrib["Port"]),
                "Address": seg.attrib["Address"],
            }
    except Exception as e:
        log.debug("Segments XML parse error: %s", e)
    return segments


# ═══════════════════════════════════════════════════════════════════════════════
#  EPG: Download & Parse Binary EPG from Multicast
# ═══════════════════════════════════════════════════════════════════════════════

def download_epg_binary(segments, iptv_ip, channels, timeout_per_day=45):
    epg = defaultdict(dict)
    total_programs = 0

    for source, seg in sorted(segments.items()):
        addr = seg["Address"]
        port = seg["Port"]
        day_match = re.search(r"EPG_(\d+)_BIN", source)
        day_num = int(day_match.group(1)) if day_match else -1
        log.info("Downloading EPG day %d from %s:%d...", day_num, addr, port)

        xml_files = download_dvb_xml(addr, port, iptv_ip, timeout=timeout_per_day)
        for fname, xml_str in xml_files.items():
            try:
                programs = parse_epg_xml(xml_str, channels)
                for ch_id, progs in programs.items():
                    epg[ch_id].update(progs)
                    total_programs += len(progs)
            except Exception as e:
                log.debug("EPG parse error for %s/%s: %s", source, fname, e)

    log.info("EPG: %d programs across %d channels", total_programs, len(epg))
    return dict(epg)


def parse_epg_xml(xml_str, channels):
    programs = defaultdict(dict)

    try:
        root = fromstring(xml_str.replace("\n", " "))
    except Exception:
        return programs

    ns_epg = "urn:dvb:ipisdns:2006"
    ns_tva = "urn:tva:metadata:2007"
    ns_mpeg = "urn:tva:metadata:cs:2007"

    for pi in root.iter(f"{{{ns_tva}}}ProgramInformation"):
        try:
            pid_attr = pi.attrib.get("programId", "")
            pid = int(re.sub(r"\D", "", pid_attr) or 0)
            if not pid:
                continue

            title_el = pi.find(f".//{{{ns_tva}}}Title")
            title = ""
            if title_el is not None and title_el.text:
                try:
                    title = title_el.text.encode("latin1").decode("utf8").strip()
                except (UnicodeDecodeError, UnicodeEncodeError):
                    title = title_el.text.strip()

            genre_el = pi.find(f".//{{{ns_tva}}}Genre/{{{ns_tva}}}Name")
            genre = ""
            if genre_el is not None and genre_el.text:
                try:
                    genre = genre_el.text.encode("latin1").decode("utf8")
                except (UnicodeDecodeError, UnicodeEncodeError):
                    genre = genre_el.text

            synopsis_el = pi.find(f".//{{{ns_tva}}}Synopsis")
            synopsis = ""
            if synopsis_el is not None and synopsis_el.text:
                try:
                    synopsis = synopsis_el.text.encode("latin1").decode("utf8").strip()
                except (UnicodeDecodeError, UnicodeEncodeError):
                    synopsis = synopsis_el.text.strip()

        except Exception:
            continue

    for sched in root.iter(f"{{{ns_tva}}}ScheduleEvent"):
        try:
            se_crid = ""
            pi_ref = sched.find(f".//{{{ns_tva}}}Program")
            if pi_ref is not None:
                se_crid = pi_ref.attrib.get("crid", "")

            pub_time_el = sched.find(f".//{{{ns_tva}}}PublishedStartTime")
            dur_el = sched.find(f".//{{{ns_tva}}}PublishedDuration")
            if pub_time_el is None or dur_el is None:
                continue

            start_str = pub_time_el.text
            start_ts = int(datetime.fromisoformat(start_str.replace("Z", "+00:00")).timestamp())

            dur_str = dur_el.text or "PT0S"
            dur_match = re.match(r"PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?", dur_str)
            duration = 0
            if dur_match:
                h, m, s = (int(x or 0) for x in dur_match.groups())
                duration = h * 3600 + m * 60 + s

            pid_ref = sched.find(f".//{{{ns_tva}}}Program")
            pid = 0
            if pid_ref is not None:
                pid_str = pid_ref.attrib.get("crid", "")
                pid = int(re.sub(r"\D", "", pid_str) or 0)

        except Exception:
            continue

    for event in root.iter("event"):
        try:
            ch_id = int(event.attrib.get("channel_id", event.attrib.get("serviceUID", 0)))
            if ch_id == 0:
                continue

            begin = int(event.attrib.get("beginTime", event.attrib.get("begin_time", 0)))
            if begin > 1e12:
                begin //= 1000
            duration = int(event.attrib.get("duration", 0))
            if duration > 1e6:
                duration //= 1000
            pid = int(event.attrib.get("extInfoID", event.attrib.get("pid", event.attrib.get("id", 0))))

            title = event.attrib.get("name", event.attrib.get("title", ""))
            try:
                title = title.encode("latin1").decode("utf8")
            except (UnicodeDecodeError, UnicodeEncodeError, AttributeError):
                pass
            title = re.sub(r"(\d+)/(\d+)", r"\1\2", title).strip()

            genre = event.attrib.get("genre", event.attrib.get("labelGenre", ""))
            genre_id = event.attrib.get("genreID", event.attrib.get("themeID", ""))

            serie = ""
            season = episode = 0
            m = re.search(r"^(.+?) S(\d+)E(\d+)", title)
            if m:
                serie, season, episode = m.group(1), int(m.group(2)), int(m.group(3))
            else:
                m = re.search(r"^(.+?) - (.+)", title)
                if m:
                    serie = m.group(1)

            if ch_id in channels or True:
                programs[ch_id][begin] = {
                    "pid": pid,
                    "duration": duration,
                    "full_title": title,
                    "genre": genre_id or genre,
                    "serie": serie,
                    "season": season,
                    "episode": episode,
                }
        except (KeyError, ValueError):
            continue

    return programs


def download_epg_from_api(endpoint, channels, proxy=None):
    epg = defaultdict(dict)
    total = 0

    for ch_id in channels:
        try:
            data = api_call(endpoint, f"getEpg&channelID={ch_id}&first=0&numItems=200", proxy)
            if not data:
                continue
            items = data if isinstance(data, list) else data.get("items", data.get("epg", []))
            if not isinstance(items, list):
                continue

            for item in items:
                begin = int(item.get("beginTime", 0))
                if begin > 1e12:
                    begin //= 1000
                duration = int(item.get("duration", 0))
                if duration > 1e6:
                    duration //= 1000
                pid = int(item.get("extInfoID", item.get("productID", 0)))
                title = item.get("name", item.get("title", ""))
                genre = item.get("labelGenre", item.get("genre", ""))
                genre_id = item.get("themeID", item.get("genreID", ""))

                serie = ""
                season = episode = 0
                m = re.search(r"^(.+?) S(\d+)E(\d+)", title)
                if m:
                    serie, season, episode = m.group(1), int(m.group(2)), int(m.group(3))

                epg[ch_id][begin] = {
                    "pid": pid,
                    "duration": duration,
                    "full_title": title,
                    "genre": genre_id or genre,
                    "serie": serie,
                    "season": season,
                    "episode": episode,
                }
                total += 1
        except Exception as e:
            log.debug("EPG API error for channel %d: %s", ch_id, e)

    log.info("EPG API: %d programs across %d channels", total, len(epg))
    return dict(epg)


# ═══════════════════════════════════════════════════════════════════════════════
#  EPG: XMLTV Generation
# ═══════════════════════════════════════════════════════════════════════════════

def generate_xmltv(channels, epg, output_path):
    tz_offset = time.timezone // -3600

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<!DOCTYPE tv SYSTEM "xmltv.dtd">',
        '<tv generator-info-name="movistar-scanner" generator-info-url="">',
    ]

    for ch_id, ch in sorted(channels.items(), key=lambda x: x[1].get("name", "")):
        name = ch.get("name", f"Channel {ch_id}")
        logo = ch.get("logo", ch.get("logo_uri", ""))
        lines.append(f'  <channel id="{ch_id}.movistar.tv">')
        lines.append(f'    <display-name>{_xml_esc(name)}</display-name>')
        if logo:
            lines.append(f'    <icon src="{_xml_esc(logo)}" />')
        lines.append(f'  </channel>')

    for ch_id in sorted(epg.keys()):
        programs = epg[ch_id]
        for ts in sorted(programs.keys()):
            p = programs[ts]
            duration = p.get("duration", 0)
            if not duration:
                continue

            dst_s = time.localtime(ts).tm_isdst
            dst_e = time.localtime(ts + duration).tm_isdst
            start = datetime.fromtimestamp(ts).strftime("%Y%m%d%H%M%S")
            stop = datetime.fromtimestamp(ts + duration).strftime("%Y%m%d%H%M%S")
            tz_s = f"+{tz_offset + dst_s:02d}00"
            tz_e = f"+{tz_offset + dst_e:02d}00"

            title = p.get("full_title", "")
            serie = p.get("serie", "")
            season = p.get("season", 0)
            episode = p.get("episode", 0)
            genre = p.get("genre", "")
            genre_name = ""
            if genre:
                genre_name = GENRE_MAP.get(str(genre)[:1], str(genre))
            year = p.get("year", 0)
            desc = p.get("desc", "")
            sub_title = p.get("sub_title", "")

            display_title = serie if serie else title

            lines.append(f'  <programme start="{start} {tz_s}" stop="{stop} {tz_e}" channel="{ch_id}.movistar.tv">')
            lines.append(f'    <title lang="es">{_xml_esc(display_title)}</title>')
            if sub_title:
                lines.append(f'    <sub-title lang="es">{_xml_esc(sub_title)}</sub-title>')
            if desc:
                lines.append(f'    <desc lang="es">{_xml_esc(desc)}</desc>')
            if genre_name:
                lines.append(f'    <category lang="es">{_xml_esc(genre_name)}</category>')
            if year:
                lines.append(f'    <date>{year}</date>')
            if season and episode:
                lines.append(f'    <episode-num system="xmltv_ns">{season - 1}.{episode - 1}.</episode-num>')
            elif episode:
                lines.append(f'    <episode-num system="xmltv_ns">.{episode - 1}.</episode-num>')
            lines.append(f'  </programme>')

    lines.append('</tv>')

    xml_str = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(xml_str)

    with gzip.open(output_path + ".gz", "wt", encoding="utf-8") as f:
        f.write(xml_str)

    log.info("XMLTV guide written: %s (%d channels)", output_path, len(epg))


def _xml_esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# ═══════════════════════════════════════════════════════════════════════════════
#  TSC Encryption Scanner
# ═══════════════════════════════════════════════════════════════════════════════

def strip_rtp(data):
    if len(data) < 12 or data[0] == TS_SYNC:
        return data
    if (data[0] >> 6) != 2:
        return data

    cc = data[0] & 0x0F
    has_padding = bool(data[0] & 0x20)
    has_extension = bool(data[0] & 0x10)

    offset = 12 + cc * 4

    if has_extension and len(data) > offset + 4:
        ext_len = (data[offset + 2] << 8) | data[offset + 3]
        offset += 4 + ext_len * 4

    end = len(data)
    if has_padding and end > offset:
        pad_count = data[-1]
        if pad_count < (end - offset):
            end -= pad_count

    return data[offset:end]


def find_ts_offset(data):
    for i in range(min(len(data), 1024)):
        if data[i] == TS_SYNC and i + TS_SIZE < len(data) and data[i + TS_SIZE] == TS_SYNC:
            return i
    return -1


def check_scrambling(data):
    offset = find_ts_offset(data)
    if offset < 0:
        return False, False

    total = scrambled = 0
    while offset + TS_SIZE <= len(data):
        if data[offset] != TS_SYNC:
            offset += 1
            continue
        pid = ((data[offset + 1] & 0x1F) << 8) | data[offset + 2]
        tsc = (data[offset + 3] >> 6) & 0x03
        if pid not in SI_PIDS:
            total += 1
            if tsc != 0:
                scrambled += 1
        offset += TS_SIZE

    return (True, scrambled > total * 0.1) if total > 0 else (True, False)


def scan_channel(addr, port, iptv_ip, timeout=1.5, attempts=8):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        sock.settimeout(timeout)
        sock.bind(("", port))
        mreq = struct.pack("4s4s", socket.inet_aton(addr), socket.inet_aton(iptv_ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        buf = bytearray()
        try:
            for _ in range(attempts):
                buf.extend(sock.recv(65535))
        except socket.timeout:
            pass

        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
        except OSError:
            pass
        sock.close()

        if not buf:
            return "offline"
        ts_data = strip_rtp(bytes(buf))
        has, scr = check_scrambling(ts_data)
        if not has:
            return "offline"
        return "encrypted" if scr else "free"
    except Exception as e:
        log.debug("scan_channel %s:%d error: %s", addr, port, e)
        return "error"


def scan_channel_udpxy(addr, port, udpxy_url, timeout=3):
    try:
        url = f"{udpxy_url.rstrip('/')}/udp/{addr}:{port}/"
        resp = urllib.request.urlopen(url, timeout=timeout)
        buf = resp.read(65535 * 8)
        resp.close()
        if not buf:
            return "offline"
        ts_data = strip_rtp(buf)
        has, scr = check_scrambling(ts_data)
        return "encrypted" if scr else "free" if has else "offline"
    except Exception:
        return "error"


# ═══════════════════════════════════════════════════════════════════════════════
#  M3U Playlist Generator
# ═══════════════════════════════════════════════════════════════════════════════

def generate_m3u(channels, output_path, base_url, epg_url=None):
    lines = ['#EXTM3U name="Movistar IPTV Free"']
    if epg_url:
        lines[0] += f' url-tvg="{epg_url}"'
    lines[0] += ' refresh="3600"'

    for ch_id, ch in sorted(channels.items(), key=lambda x: x[1].get("dial", x[1].get("name", "zzz"))):
        name = ch.get("name", f"Channel {ch_id}")
        dial = ch.get("dial", "")
        genre = ch.get("genre", "")
        logo = ch.get("logo", ch.get("logo_uri", ""))

        extras = [f'tvg-id="{ch_id}.movistar.tv"']
        extras.append(f'tvg-name="{name}"')
        if logo:
            extras.append(f'tvg-logo="{logo}"')
        if dial:
            extras.append(f'tvg-chno="{dial}"')
        if genre:
            extras.append(f'group-title="{genre}"')

        lines.append(f'#EXTINF:-1 {" ".join(extras)},{name}')

        if "://" in base_url and not base_url.startswith(("rtp://", "udp://")):
            lines.append(f'{base_url.rstrip("/")}/{ch_id}/stream')
        else:
            lines.append(f'rtp://@{ch["address"]}:{ch["port"]}')

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log.info("M3U: %s (%d channels)", output_path, len(channels))


# ═══════════════════════════════════════════════════════════════════════════════
#  Application State
# ═══════════════════════════════════════════════════════════════════════════════

class AppState:
    def __init__(self):
        self.lock = threading.Lock()
        self.all_channels = {}
        self.free_channels = {}
        self.encrypted_channels = {}
        self.offline_channels = {}
        self.epg = {}
        self.iptv_ip = None
        self.endpoint = None
        self.metadata = None
        self.scan_time = None
        self.scan_count = 0
        self.epg_time = None
        self.active_streams = {}
        self.total_served = 0
        self.start_time = datetime.now()

    def update_scan(self, free, encrypted, offline):
        with self.lock:
            self.free_channels = {ch_id: ch for ch_id, ch in free}
            self.encrypted_channels = {ch_id: ch for ch_id, ch in encrypted}
            self.offline_channels = {ch_id: ch for ch_id, ch in offline}
            self.scan_time = datetime.now()
            self.scan_count += 1

    def update_epg(self, epg):
        with self.lock:
            self.epg = epg
            self.epg_time = datetime.now()

    def stream_start(self, ch_id, client):
        with self.lock:
            if ch_id not in self.active_streams:
                self.active_streams[ch_id] = []
            self.active_streams[ch_id].append(client)
            self.total_served += 1

    def stream_stop(self, ch_id, client):
        with self.lock:
            if ch_id in self.active_streams:
                try:
                    self.active_streams[ch_id].remove(client)
                except ValueError:
                    pass
                if not self.active_streams[ch_id]:
                    del self.active_streams[ch_id]

    def get_status(self):
        with self.lock:
            uptime = str(datetime.now() - self.start_time).split(".")[0]
            return {
                "version": __version__,
                "uptime": uptime,
                "iptv_ip": self.iptv_ip,
                "channels": {
                    "total": len(self.all_channels),
                    "free": len(self.free_channels),
                    "encrypted": len(self.encrypted_channels),
                    "offline": len(self.offline_channels),
                },
                "epg": {
                    "programs": sum(len(p) for p in self.epg.values()),
                    "channels_with_epg": len(self.epg),
                    "last_update": self.epg_time.isoformat() if self.epg_time else None,
                },
                "scan": {
                    "count": self.scan_count,
                    "last": self.scan_time.isoformat() if self.scan_time else None,
                },
                "streams": {
                    "active": sum(len(v) for v in self.active_streams.values()),
                    "channels": len(self.active_streams),
                    "total_served": self.total_served,
                },
            }


# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP Proxy Server
# ═══════════════════════════════════════════════════════════════════════════════

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    server_version = "MovistarProxy/2.0"
    state: AppState = None
    output_dir: str = "."
    udpxy_url: str = None

    def log_message(self, fmt, *args):
        log.info("[HTTP] %s %s", self.client_address[0], fmt % args)

    def do_GET(self):
        path = self.path.strip("/").split("?")[0]
        parts = path.split("/")

        routes = {
            "": self._playlist, "playlist.m3u": self._playlist,
            "channels.json": self._channels_json,
            "channels_all.json": self._all_channels_json,
            "status": self._status, "guide.xml": self._guide,
            "guide.xml.gz": self._guide_gz,
            "epg.xml": self._guide, "epg.xml.gz": self._guide_gz,
        }

        if path in routes:
            routes[path]()
        elif len(parts) >= 1 and parts[0].isdigit():
            self._stream(int(parts[0]))
        else:
            self.send_error(404)

    def _send(self, body, content_type, headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _playlist(self):
        state = self.state
        host = self.headers.get("Host", self.server.server_address[0])
        base = f"http://{host}"
        epg_url = f"{base}/guide.xml.gz"

        lines = [f'#EXTM3U name="Movistar IPTV Free" url-tvg="{epg_url}" refresh="3600"']
        with state.lock:
            for ch_id, ch in sorted(state.free_channels.items(),
                                    key=lambda x: x[1].get("dial", x[1].get("name", "zzz"))):
                name = ch.get("name", str(ch_id))
                dial = ch.get("dial", "")
                genre = ch.get("genre", "")
                logo = ch.get("logo", ch.get("logo_uri", ""))
                extras = [f'tvg-id="{ch_id}.movistar.tv"']
                extras.append(f'tvg-name="{name}"')
                if logo:
                    extras.append(f'tvg-logo="{logo}"')
                if dial:
                    extras.append(f'tvg-chno="{dial}"')
                if genre:
                    extras.append(f'group-title="{genre}"')
                lines.append(f'#EXTINF:-1 {" ".join(extras)},{name}')
                lines.append(f'{base}/{ch_id}/stream')

        self._send("\n".join(lines) + "\n", "audio/x-mpegurl; charset=utf-8")

    def _channels_json(self):
        with self.state.lock:
            data = [{"id": cid, "name": ch.get("name"), "address": ch["address"],
                     "port": ch["port"], "dial": ch.get("dial", ""), "genre": ch.get("genre", "")}
                    for cid, ch in sorted(self.state.free_channels.items(),
                                          key=lambda x: x[1].get("name", ""))]
        self._send(json.dumps(data, indent=2, ensure_ascii=False), "application/json")

    def _all_channels_json(self):
        with self.state.lock:
            free_ids = set(self.state.free_channels.keys())
            enc_ids = set(self.state.encrypted_channels.keys())
            data = []
            for cid, ch in sorted(self.state.all_channels.items(), key=lambda x: x[1].get("name", "")):
                status = "free" if cid in free_ids else ("encrypted" if cid in enc_ids else "offline")
                data.append({"id": cid, "name": ch.get("name"), "status": status,
                             "address": ch["address"], "port": ch["port"],
                             "dial": ch.get("dial", ""), "genre": ch.get("genre", "")})
        self._send(json.dumps(data, indent=2, ensure_ascii=False), "application/json")

    def _status(self):
        self._send(json.dumps(self.state.get_status(), indent=2), "application/json")

    def _guide(self):
        path = os.path.join(self.output_dir, "guide.xml")
        if os.path.exists(path):
            with open(path, "rb") as f:
                self._send(f.read(), "application/xml")
        else:
            self.send_error(404, "EPG not yet available")

    def _guide_gz(self):
        path = os.path.join(self.output_dir, "guide.xml.gz")
        if os.path.exists(path):
            with open(path, "rb") as f:
                self._send(f.read(), "application/xml",
                           {"Content-Encoding": "gzip"})
        else:
            self.send_error(404, "EPG not yet available")

    def _stream(self, ch_id):
        state = self.state
        with state.lock:
            ch = state.free_channels.get(ch_id)
        if not ch:
            self.send_error(404, f"Channel {ch_id} not found or encrypted")
            return

        addr, port = ch["address"], ch["port"]
        name = ch.get("name", str(ch_id))
        client = f"{self.client_address[0]}:{self.client_address[1]}"

        if self.udpxy_url:
            self._stream_udpxy(ch_id, addr, port, name, client)
        else:
            self._stream_multicast(ch_id, addr, port, name, client)

    def _stream_multicast(self, ch_id, addr, port, name, client):
        state = self.state
        log.info("[STREAM] %s -> %s (%s:%d) multicast", client, name, addr, port)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
            sock.settimeout(5)
            sock.bind(("", port))
            mreq = struct.pack("4s4s", socket.inet_aton(addr), socket.inet_aton(state.iptv_ip))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError as e:
            self.send_error(503, str(e))
            return

        state.stream_start(ch_id, client)

        self.send_response(200)
        self.send_header("Content-Type", "video/MP2T")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Connection", "close")
        self.end_headers()

        try:
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        try:
            buf = bytearray()
            while True:
                try:
                    data = sock.recv(65535)
                except socket.timeout:
                    if buf:
                        self.wfile.write(buf)
                        self.wfile.flush()
                        buf.clear()
                    continue
                if not data:
                    break
                ts_payload = strip_rtp(data)
                buf.extend(ts_payload)
                if len(buf) >= TS_SIZE * 49:
                    self.wfile.write(buf)
                    self.wfile.flush()
                    buf.clear()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            state.stream_stop(ch_id, client)
            log.info("[STREAM] %s -x %s", client, name)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
            except OSError:
                pass
            sock.close()

    def _stream_udpxy(self, ch_id, addr, port, name, client):
        state = self.state
        url = f"{self.udpxy_url.rstrip('/')}/udp/{addr}:{port}/"
        log.info("[STREAM] %s -> %s via udpxy (%s)", client, name, url)

        try:
            upstream = urllib.request.urlopen(url, timeout=10)
        except Exception as e:
            self.send_error(502, f"udpxy error: {e}")
            return

        state.stream_start(ch_id, client)

        self.send_response(200)
        self.send_header("Content-Type", "video/MP2T")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Connection", "close")
        self.end_headers()

        try:
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        try:
            while True:
                chunk = upstream.read(TS_SIZE * 49)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            state.stream_stop(ch_id, client)
            log.info("[STREAM] %s -x %s", client, name)
            try:
                upstream.close()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
#  Background Scanner
# ═══════════════════════════════════════════════════════════════════════════════

class BackgroundScanner(threading.Thread):
    def __init__(self, state, iptv_ip, interval, output_dir, udpxy=None,
                 base_url="rtp://", proxy=None):
        super().__init__(daemon=True, name="scanner")
        self.state = state
        self.iptv_ip = iptv_ip
        self.interval = interval
        self.output_dir = output_dir
        self.udpxy = udpxy
        self.base_url = base_url
        self.proxy = proxy
        self.stop_event = threading.Event()

    def run(self):
        while not self.stop_event.is_set():
            self.stop_event.wait(self.interval)
            if self.stop_event.is_set():
                break

            log.info("Background rescan starting...")
            try:
                self._do_scan()
            except Exception as e:
                log.error("Background scan failed: %s", e)

    def _do_scan(self):
        channels = self.state.all_channels
        if not channels:
            return

        free = []
        encrypted = []
        offline = []

        for ch_id, ch in sorted(channels.items(), key=lambda x: x[1].get("name", "")):
            if self.udpxy:
                status = scan_channel_udpxy(ch["address"], ch["port"], self.udpxy)
            else:
                status = scan_channel(ch["address"], ch["port"], self.iptv_ip)

            if status == "free":
                free.append((ch_id, ch))
            elif status == "encrypted":
                encrypted.append((ch_id, ch))
            else:
                offline.append((ch_id, ch))

        old_free = set(self.state.free_channels.keys())
        new_free = {ch_id for ch_id, _ in free}

        added = new_free - old_free
        removed = old_free - new_free
        if added:
            names = [channels[cid]["name"] for cid in added if cid in channels]
            log.info("New free channels: %s", ", ".join(names))
        if removed:
            names = [channels[cid]["name"] for cid in removed if cid in channels]
            log.info("Channels no longer free: %s", ", ".join(names))

        self.state.update_scan(free, encrypted, offline)

        free_dict = {ch_id: ch for ch_id, ch in free}
        host = self.base_url if "://" in self.base_url else "rtp://"
        generate_m3u(free_dict, os.path.join(self.output_dir, "movistar_free.m3u"), host)

        if self.state.epg:
            generate_xmltv(channels, self.state.epg, os.path.join(self.output_dir, "guide.xml"))

        log.info("Rescan complete: %d free, %d encrypted, %d offline",
                 len(free), len(encrypted), len(offline))

    def stop(self):
        self.stop_event.set()


# ═══════════════════════════════════════════════════════════════════════════════
#  Metadata Discovery
# ═══════════════════════════════════════════════════════════════════════════════

def discover_metadata(iptv_ip, proxy=None):
    log.info("Discovering Movistar network...")

    endpoint = find_endpoint(proxy)
    if not endpoint:
        log.error("Cannot reach Movistar API endpoints")
        return None, None, None

    log.info("API: %s", endpoint)

    client = api_call(endpoint, "getClientProfile", proxy)
    platform = api_call(endpoint, "getPlatformProfile", proxy)

    if not client or not platform:
        log.error("Failed to get Movistar profiles")
        return None, None, None

    dem = client.get("demarcation", 0)
    pkgs = client.get("tvPackages", "")
    log.info("Demarcation: %s (%d) | Packages: %s", DEMARCATIONS.get(dem, "?"), dem, pkgs)

    dvb_ep = platform.get("dvbConfig", {}).get("dvbipiEntryPoint", "")
    if ":" not in dvb_ep:
        return None, None, None

    grp, port = dvb_ep.split(":")
    log.info("DVB entry: %s:%s", grp, port)

    dem_xml = download_dvb_xml(grp, int(port), iptv_ip, timeout=30)
    if "1_0" not in dem_xml:
        log.error("Failed DVB demarcation download")
        return None, None, None

    result = re.findall(f"DEM_{dem}" + r'\..*?Address="(.*?)".*?\s*Port="(.*?)".*?',
                        dem_xml["1_0"], re.DOTALL)
    if not result:
        return None, None, None

    sp_grp, sp_port = result[0]
    log.info("Service provider: %s:%s", sp_grp, sp_port)

    sp_xml = download_dvb_xml(sp_grp, int(sp_port), iptv_ip, timeout=60)
    channels = parse_channels_xml(sp_xml.get("2_0", ""))
    packages = parse_packages_xml(sp_xml.get("5_0", ""))
    segments = parse_segments_xml(sp_xml.get("6_0", ""))

    services = {}
    for pkg_name in pkgs.split("|") if pkgs != "ALL" else packages:
        services.update(packages.get(pkg_name, {}).get("services", {}))
    for ch_id in channels:
        if str(ch_id) in services:
            channels[ch_id]["dial"] = services[str(ch_id)]

    log.info("Discovered: %d channels, %d segments", len(channels), len(segments))
    return channels, segments, endpoint


def _parse_xmltv_time(s):
    parts = s.strip().split()
    dt = datetime.strptime(parts[0], "%Y%m%d%H%M%S")
    if len(parts) > 1:
        tz_str = parts[1]
        sign = 1 if tz_str[0] == "+" else -1
        tz_h = int(tz_str[1:3])
        tz_m = int(tz_str[3:5]) if len(tz_str) >= 5 else 0
        tz = timezone(timedelta(hours=sign * tz_h, minutes=sign * tz_m))
        dt = dt.replace(tzinfo=tz)
    return int(dt.timestamp())


def load_metadata_from_relay(udpxy_url):
    url = f"{udpxy_url.rstrip('/')}/channels"
    log.info("Fetching channel list from relay: %s", url)
    try:
        resp = urllib.request.urlopen(url, timeout=15)
        data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        log.error("Failed to fetch channels from relay: %s", e)
        return None, {}, {}

    raw = data.get("data", data)
    channels = raw.get("channels", {})
    result = {}
    for k, v in channels.items():
        if isinstance(v, dict) and "address" in v:
            ch_id = int(k)
            v["id"] = ch_id
            result[ch_id] = v

    if not result:
        log.error("Relay returned 0 channels (discovery still running?)")
        return None, {}, {}

    log.info("Loaded %d channels from relay", len(result))

    epg = {}
    epg_url = f"{udpxy_url.rstrip('/')}/guide.xml"
    log.info("Fetching EPG from relay: %s", epg_url)
    try:
        resp = urllib.request.urlopen(epg_url, timeout=30)
        xmltv = resp.read().decode("utf-8")
        root = fromstring(xmltv)
        for prog in root.findall("programme"):
            ch_tag = prog.get("channel", "")
            ch_id = int(ch_tag.split(".")[0]) if "." in ch_tag else 0
            if ch_id == 0:
                continue
            start_raw = prog.get("start", "")
            stop_raw = prog.get("stop", "")
            try:
                begin = _parse_xmltv_time(start_raw)
            except Exception:
                continue
            try:
                end = _parse_xmltv_time(stop_raw)
            except Exception:
                end = begin + 3600
            title_el = prog.find("title")
            title = title_el.text if title_el is not None and title_el.text else ""
            sub_el = prog.find("sub-title")
            desc_el = prog.find("desc")
            cat_el = prog.find("category")
            date_el = prog.find("date")
            epnum_el = prog.find("episode-num")

            serie = title
            season = 0
            episode = 0
            if epnum_el is not None and epnum_el.text:
                parts = epnum_el.text.split(".")
                try:
                    season = int(parts[0]) + 1 if parts[0].strip() else 0
                except ValueError:
                    pass
                try:
                    episode = int(parts[1]) + 1 if len(parts) > 1 and parts[1].strip() else 0
                except ValueError:
                    pass
            try:
                year = int(date_el.text) if date_el is not None and date_el.text else 0
            except ValueError:
                year = 0

            if ch_id not in epg:
                epg[ch_id] = {}
            epg[ch_id][begin] = {
                "pid": 0,
                "duration": end - begin,
                "full_title": title,
                "genre": cat_el.text if cat_el is not None and cat_el.text else "",
                "serie": serie,
                "season": season,
                "episode": episode,
                "year": year,
                "desc": desc_el.text if desc_el is not None and desc_el.text else "",
                "sub_title": sub_el.text if sub_el is not None and sub_el.text else "",
            }
        log.info("Loaded EPG from relay: %d channels, %d programs",
                 len(epg), sum(len(p) for p in epg.values()))
    except Exception as e:
        log.warning("Failed to fetch EPG from relay: %s", e)

    return result, {}, epg


def load_metadata_file(path):
    with open(path) as f:
        data = json.load(f)
    raw = data.get("data", data)
    channels = raw.get("channels", {})
    segments = raw.get("segments", {})
    result = {}
    for k, v in channels.items():
        if isinstance(v, dict) and "address" in v:
            ch_id = int(k)
            v["id"] = ch_id
            result[ch_id] = v

    parent = os.path.dirname(path)
    cfg_path = os.path.join(parent, "config.json")
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path) as f:
                cfg = json.load(f).get("data", {})
            log.info("Loaded config from %s (demarcation=%s)", cfg_path,
                     cfg.get("demarcation", "?"))
        except Exception as e:
            log.debug("config.json load error: %s", e)

    epg_path = os.path.join(parent, "epg.json")
    epg_cache = {}
    if os.path.exists(epg_path):
        try:
            with open(epg_path) as f:
                epg_raw = json.load(f)
            epg_data = epg_raw.get("data", epg_raw)
            for ch_id_s, progs in epg_data.items():
                if isinstance(progs, dict):
                    ch_id = int(ch_id_s)
                    epg_cache[ch_id] = {int(ts): p for ts, p in progs.items()}
            log.info("Loaded cached EPG: %d channels from %s",
                     len(epg_cache), epg_path)
        except Exception as e:
            log.debug("epg.json load error: %s", e)

    return result, segments, epg_cache


# ═══════════════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(
        description="Movistar IPTV Scanner & Proxy v" + __version__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --serve                                Full service (scan + proxy + EPG)
  %(prog)s --serve --daemon --interval 3600       + periodic rescan
  %(prog)s --serve --proxy socks5://host:1080     Via SOCKS5
  %(prog)s --metadata epg_metadata.json --serve   From local file
  %(prog)s                                        Scan only, no proxy

Proxy endpoints:
  /playlist.m3u        M3U playlist (free channels)
  /channels.json       Free channels as JSON
  /channels_all.json   All channels with status
  /guide.xml[.gz]      XMLTV EPG guide (all channels)
  /<id>/stream         Live MPEG-TS stream
  /status              Server status & stats
        """)

    g = p.add_argument_group("Network")
    g.add_argument("--proxy", help="SOCKS5 proxy (socks5://[user:pass@]host:port)")
    g.add_argument("--udpxy", help="udpxy relay URL (http://host:port)")
    g.add_argument("--iptv-ip", help="IPTV interface IP (auto-detected)")

    g = p.add_argument_group("Data")
    g.add_argument("--metadata", help="Local metadata JSON (epg_metadata.json)")

    g = p.add_argument_group("Server")
    g.add_argument("--serve", "-s", action="store_true", help="Start HTTP proxy")
    g.add_argument("--listen", default="0.0.0.0", help="Listen address (0.0.0.0)")
    g.add_argument("--port", "-p", type=int, default=8888, help="Listen port (8888)")

    g = p.add_argument_group("Daemon")
    g.add_argument("--daemon", "-d", action="store_true", help="Periodic rescan")
    g.add_argument("--interval", "-i", type=int, default=3600, help="Rescan interval (3600s)")
    g.add_argument("--no-epg", action="store_true", help="Skip EPG download")

    g = p.add_argument_group("Output")
    g.add_argument("--output-dir", "-o", default=".", help="Output directory")
    g.add_argument("--base-url", default=None, help="M3U base URL")

    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--quiet", "-q", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    args = p.parse_args()

    level = logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO)
    logging.basicConfig(level=level, format="[%(asctime)s] %(levelname)-8s %(message)s",
                        datefmt="%H:%M:%S")

    os.makedirs(args.output_dir, exist_ok=True)

    proxy = ProxyConfig(args.proxy) if args.proxy else None
    state = AppState()

    # --- Detect IPTV ---
    iptv_ip = args.iptv_ip or detect_iptv_ip()
    if not iptv_ip and not args.udpxy:
        log.error("Cannot detect IPTV network. Use --iptv-ip or --udpxy")
        sys.exit(1)
    state.iptv_ip = iptv_ip
    log.info("IPTV IP: %s", iptv_ip)

    # --- Load channels ---
    segments = {}
    endpoint = None

    epg_preloaded = {}
    if args.metadata:
        channels, segments, epg_preloaded = load_metadata_file(args.metadata)
    elif args.udpxy:
        channels, segments, epg_preloaded = load_metadata_from_relay(args.udpxy)
        if not channels:
            log.error("Cannot get channels from relay. Is it running? Discovery complete?")
            sys.exit(1)
    else:
        channels, segments, endpoint = discover_metadata(iptv_ip, proxy)
        if not channels:
            log.error("Discovery failed")
            sys.exit(1)
        state.endpoint = endpoint

    state.all_channels = channels
    log.info("Loaded %d channels", len(channels))

    # --- Quick connectivity test ---
    test_ch = next(iter(channels.values()))
    if args.udpxy:
        log.info("Testing udpxy connectivity: %s -> %s:%d ...",
                 args.udpxy, test_ch["address"], test_ch["port"])
        test_result = scan_channel_udpxy(test_ch["address"], test_ch["port"],
                                         args.udpxy, timeout=5)
        if test_result == "error":
            log.error("udpxy test FAILED. Check URL: %s", args.udpxy)
            log.error("The relay must be running and reachable from this machine")
            sys.exit(1)
        elif test_result == "offline":
            log.warning("udpxy test: no data from %s. Relay running? IPTV VLAN connected?",
                        test_ch["address"])
        else:
            log.info("udpxy OK (%s: %s)", test_ch.get("name", "?"), test_result)
    else:
        log.info("Testing multicast connectivity: %s:%d via %s ...",
                 test_ch["address"], test_ch["port"], iptv_ip)
        test_result = scan_channel(test_ch["address"], test_ch["port"], iptv_ip,
                                   timeout=3, attempts=12)
        if test_result == "error":
            log.error("Multicast test FAILED (error). Need sudo? Wrong --iptv-ip?")
            log.error("Try: sudo %s --iptv-ip 192.168.2.5 %s",
                      sys.argv[0], " ".join(sys.argv[1:]))
            sys.exit(1)
        elif test_result == "offline":
            log.warning("Multicast test: no data from %s. Check --iptv-ip (%s)",
                        test_ch["address"], iptv_ip)
        else:
            log.info("Multicast OK (%s: %s)", test_ch.get("name", "?"), test_result)

    base_url = args.base_url or (f"http://{args.listen}:{args.port}" if args.serve else "rtp://")

    # --- Load pre-existing EPG if available ---
    if epg_preloaded:
        state.update_epg(epg_preloaded)
        log.info("EPG pre-loaded from relay: %d channels, %d programs",
                 len(epg_preloaded), sum(len(p) for p in epg_preloaded.values()))
        generate_xmltv(channels, epg_preloaded, os.path.join(args.output_dir, "guide.xml"))

    # --- Start proxy BEFORE scan (non-blocking) ---
    if args.serve:
        ProxyHandler.state = state
        ProxyHandler.output_dir = args.output_dir
        ProxyHandler.udpxy_url = args.udpxy
        server = http.server.ThreadingHTTPServer((args.listen, args.port), ProxyHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True, name="http")
        server_thread.start()

        mode = "udpxy" if args.udpxy else "multicast"
        print(f"Proxy: http://{args.listen}:{args.port} (streams via {mode})")
        print(f"  Playlist:  http://{args.listen}:{args.port}/playlist.m3u")
        print(f"  EPG:       http://{args.listen}:{args.port}/guide.xml.gz")
        print(f"  Status:    http://{args.listen}:{args.port}/status\n")

    # --- Initial scan (non-blocking in serve+daemon mode) ---
    def _do_initial_scan():
        log.info("Scanning %d channels (TSC encryption check)...", len(channels))
        free, encrypted, offline, errors = [], [], [], []
        for i, (ch_id, ch) in enumerate(sorted(channels.items(), key=lambda x: x[1].get("name", "")), 1):
            name = ch.get("name", str(ch_id))
            if not args.serve:
                sys.stdout.write(f"\r[{i}/{len(channels)}] {name:<40}")
                sys.stdout.flush()

            if args.udpxy:
                st = scan_channel_udpxy(ch["address"], ch["port"], args.udpxy)
            else:
                st = scan_channel(ch["address"], ch["port"], iptv_ip)

            if st == "free":
                free.append((ch_id, ch))
                if args.serve:
                    state.update_scan(free, encrypted, offline)
            elif st == "encrypted":
                encrypted.append((ch_id, ch))
            elif st == "error":
                errors.append((ch_id, ch))
            else:
                offline.append((ch_id, ch))

            if i % 50 == 0 and args.serve:
                state.update_scan(free, encrypted, offline)
                log.info("Scan progress: %d/%d (%d free)", i, len(channels), len(free))

        state.update_scan(free, encrypted, offline)
        log.info("Scan complete: %d free, %d encrypted, %d offline, %d errors",
                 len(free), len(encrypted), len(offline), len(errors))

        epg_url = f"http://{args.listen}:{args.port}/guide.xml.gz" if args.serve else None
        free_dict = {ch_id: ch for ch_id, ch in free}
        generate_m3u(free_dict, os.path.join(args.output_dir, "movistar_free.m3u"), base_url, epg_url)

        if not args.no_epg and not epg_preloaded:
            epg = {}
            cached_epg = os.path.join(args.output_dir, "epg_cache.json")
            if os.path.exists(cached_epg):
                age = time.time() - os.path.getmtime(cached_epg)
                if age < 3600:
                    log.info("Using cached EPG (%.0f min old)", age / 60)
                    try:
                        with open(cached_epg) as f:
                            raw = json.load(f)
                        epg = {int(k): {int(ts): v for ts, v in progs.items()} for k, progs in raw.items()}
                    except Exception:
                        epg = {}

            if not epg:
                if segments and iptv_ip:
                    epg = download_epg_binary(segments, iptv_ip, channels)
                if not epg and endpoint:
                    epg = download_epg_from_api(endpoint, channels.keys(), proxy)
                if epg:
                    try:
                        with open(cached_epg, "w") as f:
                            json.dump(epg, f, ensure_ascii=False)
                    except Exception:
                        pass

            if epg:
                state.update_epg(epg)
                generate_xmltv(channels, epg, os.path.join(args.output_dir, "guide.xml"))

    if args.serve and args.daemon:
        scan_thread = threading.Thread(target=_do_initial_scan, daemon=True, name="initial-scan")
        scan_thread.start()
        log.info("Initial scan started in background")
    else:
        _do_initial_scan()
        if not args.serve and not args.daemon:
            sys.exit(0)

    # --- Start background scanner ---
    bg_scanner = None
    if args.daemon:
        bg_scanner = BackgroundScanner(
            state, iptv_ip, args.interval, args.output_dir,
            udpxy=args.udpxy, base_url=base_url, proxy=proxy)
        bg_scanner.start()
        log.info("Background scanner: every %ds", args.interval)

    # --- Wait ---
    stop = threading.Event()
    def _sig(s, f):
        log.info("Shutting down...")
        stop.set()
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    try:
        stop.wait()
    except KeyboardInterrupt:
        pass

    if bg_scanner:
        bg_scanner.stop()
    if args.serve:
        server.shutdown()

    log.info("Stopped.")


if __name__ == "__main__":
    main()
