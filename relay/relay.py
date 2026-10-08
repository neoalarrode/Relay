#!/usr/bin/env python3
"""
Movistar IPTV Multicast-to-HTTP Relay
Home Assistant Add-on

Converts multicast RTP/UDP IPTV streams to plain HTTP MPEG-TS.
On startup discovers all channels from the Movistar DVB network
and serves the metadata so remote scanners need only this URL.

Endpoints:
  GET /udp/<addr>:<port>/   Stream multicast channel as HTTP
  GET /channels             Channel list (JSON) - auto-discovered
  GET /guide.xml            EPG guide (XMLTV) - all channels
  GET /status               Relay status (JSON)
"""

import argparse
import gzip
import io
import json
import re
import socket
import struct
import sys
import threading
import time
import urllib.request
from collections import defaultdict
from datetime import datetime
from html import unescape
from http.server import HTTPServer, BaseHTTPRequestHandler
from xml.etree.ElementTree import fromstring

TS_SYNC = 0x47
TS_SIZE = 188
IPTV_DNS = "172.26.23.3"
IPTV_RES_HOST = "172.26.22.23"
UA = "libcurl-agent/1.0 [IAL] WidgetManager Safari/538.1 CAP:803fd12a 1"

END_POINTS = (
    "http://portalnc.imagenio.telefonica.net:2001",
    "http://asiptvnc.imagenio.telefonica.net:2070",
    "http://reg360.imagenio.telefonica.net:2070",
)

LOGO_DEFAULTS = {
    "res_base": f"http://{IPTV_RES_HOST}/appclientv/nux/",
    "logo_path": "incoming/epg/channelLogo/",
}

GENRE_MAP = {
    "0": "Otros", "1": "Cine", "2": "Noticias", "3": "Entretenimiento",
    "4": "Deportes", "5": "Infantil", "6": "Musica", "7": "Cultura",
    "8": "Sociedad", "9": "Educacion", "a": "Ocio", "b": "Especial",
}


# ── Network detection ────────────────────────────────────────────────────────

def detect_iptv_ip():
    for dns in (IPTV_DNS, "172.23.3.3"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.connect((dns, 53))
                return s.getsockname()[0]
        except OSError:
            continue
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect(("8.8.8.8", 53))
            return s.getsockname()[0]
    except OSError:
        pass
    return None


# ── RTP stripping ────────────────────────────────────────────────────────────

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


# ── Movistar DVB metadata discovery ──────────────────────────────────────────

def http_get(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    resp = urllib.request.urlopen(req, timeout=timeout)
    return resp.read().decode("utf-8")


def api_call(endpoint, action):
    try:
        data = http_get(f"{endpoint}?action={action}")
        return json.loads(unescape(data)).get("resultData")
    except Exception as e:
        print(f"[discovery] API {action} failed: {e}", flush=True)
        return None


def find_endpoint():
    for ep in END_POINTS:
        try:
            http_get(ep + "/appserver/mvtv.do?action=getClientProfile", timeout=5)
            return ep + "/appserver/mvtv.do"
        except Exception:
            continue
    return None


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
                if si is not None:
                    name_el = si.find(f"{{{ns}}}Name")
                    if name_el is not None and name_el.text:
                        try:
                            name = name_el.text.encode("latin1").decode("utf8").strip(" .*")
                        except (UnicodeDecodeError, UnicodeEncodeError):
                            name = name_el.text.strip(" .*")

                genre = ""
                if si is not None:
                    genre_parent = si.find(f"{{{ns}}}Genre")
                    genre_el = genre_parent.find(f"{{{ns}}}Name") if genre_parent is not None else None
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
                    "logo": ti.attrib.get("logoURI", ""),
                }

                repl_parent = si if si is not None else svc
                repl = repl_parent.find(f".//{{{ns}}}ReplacementService")
                if repl is not None:
                    repl_ti = repl.find(f"{{{ns}}}TextualIdentifier")
                    if repl_ti is not None:
                        channels[ch_id]["replacement"] = int(
                            repl_ti.attrib.get("ServiceName", "0"))
            except (KeyError, ValueError, AttributeError):
                continue

        named = sum(1 for c in channels.values() if not c["name"].startswith("Channel "))
        print(f"[discovery] XML parse: {len(channels)} channels, {named} with names", flush=True)
    except Exception as e:
        print(f"[discovery] Channel XML parse error: {e}", flush=True)
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
        print(f"[discovery] Package XML parse error: {e}", flush=True)
    return packages


def enrich_names_from_api(endpoint, channels):
    """Fetch channel names from Movistar EPG API for channels missing names."""
    missing = [cid for cid, ch in channels.items() if ch["name"].startswith("Channel ")]
    if not missing:
        return
    print(f"[discovery] Enriching {len(missing)} channels from API...", flush=True)
    found = 0
    for cid in missing:
        try:
            data = api_call(endpoint, f"getEpg&channelID={cid}&first=0&numItems=1")
            if not data:
                continue
            items = data if isinstance(data, list) else data.get("items", data.get("epg", []))
            if items and isinstance(items, list) and len(items) > 0:
                name = items[0].get("channelName", items[0].get("channel", ""))
                if name:
                    try:
                        name = name.encode("latin1").decode("utf8")
                    except (UnicodeDecodeError, UnicodeEncodeError):
                        pass
                    channels[cid]["name"] = name.strip()
                    found += 1
        except Exception:
            continue
    print(f"[discovery] API enrichment: {found}/{len(missing)} names resolved", flush=True)


# ── EPG: Download & Parse ───────────────────────────────────────────────────

def parse_segments_xml(xml_str):
    segments = {}
    ns = "urn:dvb:ipisdns:2006"
    try:
        root = fromstring(xml_str.replace("\n", " "))
        for seg in root.iter(f"{{{ns}}}DVBBINSTP"):
            source = seg.attrib.get("Source", "")
            if "EPG" in source:
                segments[source] = {
                    "Source": source,
                    "Port": int(seg.attrib["Port"]),
                    "Address": seg.attrib["Address"],
                }
    except Exception as e:
        print(f"[epg] Segments XML parse error: {e}", flush=True)
    return segments


_EPG_XOR = 0x15


def _xor_decode(raw):
    return bytes([b ^ _EPG_XOR for b in raw])


def parse_epg_binary_data(latin1_str, channels):
    programs = defaultdict(dict)
    try:
        raw = latin1_str.encode("latin1")
    except (UnicodeEncodeError, AttributeError):
        return programs

    ch_match = re.search(rb"(\d+)\.imagenio\.es", raw)
    if not ch_match:
        return programs
    try:
        ch_id = int(ch_match.group(1))
    except ValueError:
        return programs
    if ch_id not in channels:
        return programs

    data = raw[ch_match.end():]
    pos = 0
    while pos < len(data) - 10:
        if data[pos] not in (0xDA, 0xDB):
            pos += 1
            continue

        if pos + 9 > len(data):
            break
        event_id = struct.unpack(">H", data[pos + 1:pos + 3])[0]
        begin = struct.unpack(">I", data[pos + 3:pos + 7])[0]
        duration = struct.unpack(">H", data[pos + 7:pos + 9])[0]

        if not (1700000000 < begin < 1900000000) or duration > 86400:
            pos += 1
            continue

        f1 = data.find(0xF1, pos + 15)
        if f1 == -1 or f1 - pos > 500:
            pos += 1
            continue

        title = ""
        genre_val = ""
        scan = pos + 15
        while scan < f1 - 2:
            tag = data[scan]
            if scan + 3 > len(data):
                break
            tlen = struct.unpack(">H", data[scan + 1:scan + 3])[0]
            if tlen > 400 or scan + 3 + tlen > len(data):
                scan += 1
                continue
            val = data[scan + 3:scan + 3 + tlen]
            if tag == 0x54 and tlen >= 2:
                genre_val = f"{val[-1]:02x}"
            elif tag == 0x4D and tlen >= 5:
                title_len = val[3]
                if title_len <= tlen - 4:
                    title_raw = val[4:4 + title_len]
                    try:
                        title = _xor_decode(title_raw).decode("utf-8", errors="replace")
                    except Exception:
                        title = ""
            scan += 3 + tlen
            if tag in (0x54, 0x55, 0x4D):
                continue
            break

        if not title:
            pos = f1 + 1
            continue

        title = title.strip()
        serie = ""
        season = episode = 0
        m = re.search(r"^(.+?) S(\d+)E(\d+)", title)
        if m:
            serie, season, episode = m.group(1), int(m.group(2)), int(m.group(3))
        te_m = re.search(r"(.+?) T(\d+)\s*Ep\.?\s*(\d+)", title)
        if te_m and not serie:
            serie = te_m.group(1).strip()
            season = int(te_m.group(2))
            episode = int(te_m.group(3))
        elif not serie:
            ep_m = re.search(r"(.+?) Ep\.?\s*(\d+)", title)
            if ep_m:
                serie = ep_m.group(1).strip()
                episode = int(ep_m.group(2))

        year = 0
        description = ""
        f3 = data.find(0xF3, f1)

        post = data[f1 + 1:f3] if f3 != -1 and f3 > f1 else b""
        if len(post) >= 10:
            for yi in range(len(post) - 1):
                yv = struct.unpack(">H", post[yi:yi + 2])[0]
                if 1920 <= yv <= 2999:
                    year = yv
                    break

            best_run = ""
            run_start = -1
            for di in range(len(post)):
                db = post[di] ^ _EPG_XOR
                if 0x20 <= db <= 0x7E or db >= 0x80:
                    if run_start == -1:
                        run_start = di
                else:
                    if run_start != -1 and di - run_start >= 5:
                        candidate = _xor_decode(post[run_start:di])
                        try:
                            txt = candidate.decode("utf-8", errors="replace").strip()
                        except Exception:
                            txt = ""
                        if len(txt) > len(best_run):
                            best_run = txt
                    run_start = -1
            if run_start != -1 and len(post) - run_start >= 5:
                candidate = _xor_decode(post[run_start:])
                try:
                    txt = candidate.decode("utf-8", errors="replace").strip()
                except Exception:
                    txt = ""
                if len(txt) > len(best_run):
                    best_run = txt
            description = best_run

        sub_title = ""
        if serie and title != serie:
            sub_part = title.replace(serie, "").strip()
            sub_part = re.sub(r"^[TS]\d+\s*", "", sub_part)
            sub_part = re.sub(r"^Ep\.?\s*\d+\s*", "", sub_part)
            sub_part = sub_part.strip(" -–—/")
            if sub_part:
                sub_title = sub_part

        programs[ch_id][begin] = {
            "pid": event_id,
            "duration": duration,
            "full_title": title,
            "genre": genre_val,
            "serie": serie,
            "season": season,
            "episode": episode,
            "year": year,
            "desc": description,
            "sub_title": sub_title,
        }

        if f3 != -1:
            stover = data.find(b"STOVER", f3)
            pos = (stover + 6) if stover != -1 and stover - f3 < 30 else f3 + 1
        else:
            pos = f1 + 1

    return programs


def download_epg_binary(segments, iptv_ip, channels, timeout_per_day=45):
    epg = defaultdict(dict)
    total_programs = 0

    for source, seg in sorted(segments.items()):
        addr = seg["Address"]
        port = seg["Port"]
        day_match = re.search(r"EPG_(\d+)_BIN", source)
        day_num = int(day_match.group(1)) if day_match else -1
        print(f"[epg] Downloading EPG day {day_num} from {addr}:{port}...", flush=True)

        dvb_files = download_dvb_xml(addr, port, iptv_ip, timeout=timeout_per_day)
        day_programs = 0
        for fname, data_str in dvb_files.items():
            try:
                programs = parse_epg_binary_data(data_str, channels)
                for ch_id, progs in programs.items():
                    epg[ch_id].update(progs)
                    day_programs += len(progs)
                    total_programs += len(progs)
            except Exception as e:
                print(f"[epg] Parse error {source}/{fname}: {e}", flush=True)
        print(f"[epg] Day {day_num}: {len(dvb_files)} files, "
              f"{day_programs} programs", flush=True)

    print(f"[epg] Binary EPG: {total_programs} programs across "
          f"{len(epg)} channels", flush=True)
    return dict(epg)


def download_epg_from_api(endpoint, channels):
    epg = defaultdict(dict)
    total = 0
    errors = 0
    for ch_id in channels:
        try:
            data = api_call(endpoint, f"getEpg&channelID={ch_id}&first=0&numItems=200")
            if not data:
                errors += 1
                if errors >= 10:
                    break
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
                title = item.get("name", item.get("title", ""))
                genre = item.get("labelGenre", item.get("genre", ""))
                genre_id = item.get("themeID", item.get("genreID", ""))

                serie = ""
                season = episode = 0
                m = re.search(r"^(.+?) S(\d+)E(\d+)", title)
                if m:
                    serie, season, episode = m.group(1), int(m.group(2)), int(m.group(3))

                desc = item.get("description", item.get("shortDescription", ""))
                year_str = item.get("productionDate", item.get("year", ""))
                try:
                    api_year = int(str(year_str)[:4]) if year_str else 0
                except ValueError:
                    api_year = 0

                epg[ch_id][begin] = {
                    "pid": int(item.get("extInfoID", item.get("productID", 0))),
                    "duration": duration,
                    "full_title": title,
                    "genre": genre_id or genre,
                    "serie": serie,
                    "season": season,
                    "episode": episode,
                    "year": api_year,
                    "desc": desc,
                    "sub_title": "",
                }
                total += 1
        except Exception:
            continue

    print(f"[epg] API: {total} programs across {len(epg)} channels", flush=True)
    return dict(epg)


def _xml_esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def generate_xmltv(channels, epg):
    tz_offset = time.timezone // -3600

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<!DOCTYPE tv SYSTEM "xmltv.dtd">',
        '<tv generator-info-name="movistar-relay" generator-info-url="">',
    ]

    for ch_id, ch in sorted(channels.items(), key=lambda x: x[1].get("name", "")):
        name = ch.get("name", f"Channel {ch_id}")
        logo = ch.get("logo", "")
        if logo and not logo.startswith("http") and not logo.startswith("/"):
            logo = f"/logo/{logo}"
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
                genre_name = GENRE_MAP.get(str(genre)[:1], "")
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
    return "\n".join(lines)


def get_logo_base_url(endpoint):
    try:
        platform = api_call(endpoint, "getPlatformProfile")
        config = api_call(endpoint, "getConfigurationParams")
        if platform and config:
            res_base = platform.get("RES_BASE_URI") or platform.get("res_BASE_URI", "")
            logo_path = config.get("tvChannelLogoPath", LOGO_DEFAULTS["logo_path"])
            if res_base:
                try:
                    from urllib.parse import urlparse, urlunparse
                    parsed = urlparse(res_base)
                    resolved = urlunparse(parsed._replace(netloc=IPTV_RES_HOST))
                    base = resolved.rstrip("/") + "/" + logo_path
                except Exception:
                    base = LOGO_DEFAULTS["res_base"] + logo_path
                print(f"[discovery] Logo base URL: {base}", flush=True)
                return base
    except Exception as e:
        print(f"[discovery] Logo URL fetch error: {e}", flush=True)
    base = LOGO_DEFAULTS["res_base"] + LOGO_DEFAULTS["logo_path"]
    print(f"[discovery] Using default logo base: {base}", flush=True)
    return base


def discover_channels(iptv_ip):
    print("[discovery] Discovering Movistar network...", flush=True)

    endpoint = find_endpoint()
    if not endpoint:
        print("[discovery] Cannot reach Movistar API", flush=True)
        return {}, {}, None, ""

    print(f"[discovery] API: {endpoint}", flush=True)

    client = api_call(endpoint, "getClientProfile")
    platform = api_call(endpoint, "getPlatformProfile")
    if not client or not platform:
        print("[discovery] Failed to get profiles", flush=True)
        return {}, {}, None, ""

    dem = client.get("demarcation", 0)
    pkgs = client.get("tvPackages", "")
    print(f"[discovery] Demarcation: {dem} | Packages: {pkgs}", flush=True)

    logo_base = get_logo_base_url(endpoint)

    dvb_ep = platform.get("dvbConfig", {}).get("dvbipiEntryPoint", "")
    if ":" not in dvb_ep:
        print("[discovery] No DVB entry point", flush=True)
        return {}, {}, None, logo_base

    grp, port = dvb_ep.split(":")
    print(f"[discovery] DVB entry: {grp}:{port}", flush=True)

    dem_xml = download_dvb_xml(grp, int(port), iptv_ip, timeout=30)
    if "1_0" not in dem_xml:
        print("[discovery] Failed DVB demarcation download", flush=True)
        return {}, {}, None, logo_base

    result = re.findall(
        f"DEM_{dem}" + r'\..*?Address="(.*?)".*?\s*Port="(.*?)".*?',
        dem_xml["1_0"], re.DOTALL)
    if not result:
        print(f"[discovery] Demarcation {dem} not found in DVB data", flush=True)
        return {}, {}, None, logo_base

    sp_grp, sp_port = result[0]
    print(f"[discovery] Service provider: {sp_grp}:{sp_port}", flush=True)

    sp_xml = download_dvb_xml(sp_grp, int(sp_port), iptv_ip, timeout=60)
    sp_files = sorted(sp_xml.keys())
    print(f"[discovery] SP files downloaded: {sp_files}", flush=True)
    xml_2_0 = sp_xml.get("2_0", "")
    if xml_2_0:
        print(f"[discovery] SP 2_0 size: {len(xml_2_0)} chars", flush=True)
        print(f"[discovery] SP 2_0 preview: {xml_2_0[:300]}", flush=True)

    channels = parse_channels_xml(xml_2_0)
    packages = parse_packages_xml(sp_xml.get("5_0", ""))

    services = {}
    for pkg_name in pkgs.split("|") if pkgs != "ALL" else packages:
        services.update(packages.get(pkg_name, {}).get("services", {}))
    for ch_id in channels:
        if str(ch_id) in services:
            channels[ch_id]["dial"] = services[str(ch_id)]

    named = sum(1 for c in channels.values() if not c["name"].startswith("Channel "))
    if named < len(channels) // 2:
        enrich_names_from_api(endpoint, channels)

    segments = parse_segments_xml(sp_xml.get("6_0", ""))
    print(f"[discovery] EPG segments: {len(segments)}", flush=True)

    print(f"[discovery] Found {len(channels)} channels", flush=True)
    return channels, segments, endpoint, logo_base


# ── State ────────────────────────────────────────────────────────────────────

class RelayState:
    def __init__(self):
        self.lock = threading.Lock()
        self.active = {}
        self.total_served = 0
        self.start_time = time.time()
        self.bytes_relayed = 0
        self.channels = {}
        self.channels_time = None
        self.epg = {}
        self.epg_time = None
        self.xmltv = ""
        self.xmltv_gz = b""
        self.logo_base = LOGO_DEFAULTS["res_base"] + LOGO_DEFAULTS["logo_path"]
        self._logo_cache = {}
        self._logo_lock = threading.Lock()

    def set_channels(self, channels):
        with self.lock:
            self.channels = channels
            self.channels_time = time.time()

    def get_channels(self):
        with self.lock:
            return dict(self.channels)

    def set_epg(self, epg, channels):
        with self.lock:
            self.epg = epg
            self.epg_time = time.time()
            xmltv = generate_xmltv(channels, epg)
            self.xmltv = xmltv
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
                gz.write(xmltv.encode("utf-8"))
            self.xmltv_gz = buf.getvalue()
            try:
                with open("/data/epg_cache.json", "w") as f:
                    json.dump({str(k): v for k, v in epg.items()}, f)
            except Exception:
                pass
            print(f"[epg] XMLTV generated: {len(epg)} channels, "
                  f"{sum(len(p) for p in epg.values())} programs", flush=True)

    def get_xmltv_gz(self):
        with self.lock:
            return self.xmltv_gz

    def get_xmltv(self):
        with self.lock:
            return self.xmltv

    def get_logo(self, filename):
        with self._logo_lock:
            cached = self._logo_cache.get(filename)
            if cached:
                return cached
        url = self.logo_base + filename
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            resp = urllib.request.urlopen(req, timeout=10)
            data = resp.read()
            ctype = resp.headers.get("Content-Type", "image/jpeg")
            with self._logo_lock:
                if len(self._logo_cache) < 1000:
                    self._logo_cache[filename] = (data, ctype)
            return (data, ctype)
        except Exception as e:
            print(f"[logo] Failed to fetch {url}: {e}", flush=True)
            return None

    def connect(self, key, client):
        with self.lock:
            if key not in self.active:
                self.active[key] = []
            self.active[key].append(client)
            self.total_served += 1

    def disconnect(self, key, client):
        with self.lock:
            if key in self.active:
                try:
                    self.active[key].remove(client)
                except ValueError:
                    pass
                if not self.active[key]:
                    del self.active[key]

    def add_bytes(self, n):
        with self.lock:
            self.bytes_relayed += n

    def status(self):
        with self.lock:
            uptime = int(time.time() - self.start_time)
            h, m = divmod(uptime, 3600)
            m, s = divmod(m, 60)
            mb = self.bytes_relayed / (1024 * 1024)
            return {
                "version": "1.0.9",
                "uptime": f"{h}h {m}m {s}s",
                "channels_discovered": len(self.channels),
                "channels_updated": time.strftime(
                    "%Y-%m-%d %H:%M", time.localtime(self.channels_time)
                ) if self.channels_time else None,
                "epg_channels": len(self.epg),
                "epg_programs": sum(len(p) for p in self.epg.values()),
                "epg_updated": time.strftime(
                    "%Y-%m-%d %H:%M", time.localtime(self.epg_time)
                ) if self.epg_time else None,
                "active_streams": sum(len(v) for v in self.active.values()),
                "active_channels": list(self.active.keys()),
                "total_served": self.total_served,
                "bytes_relayed_mb": round(mb, 1),
                "logo_base": self.logo_base,
                "logo_cached": len(self._logo_cache),
            }


# ── HTTP handler ─────────────────────────────────────────────────────────────

class RelayHandler(BaseHTTPRequestHandler):
    server_version = "MovistarRelay/1.0"
    interface = "0.0.0.0"
    buffer_kb = 1024
    max_clients = 10
    state = None

    def log_message(self, fmt, *args):
        print(f"[relay] {self.client_address[0]} {fmt % args}", flush=True)

    def do_GET(self):
        path = self.path.rstrip("/").split("?")[0]

        m = re.match(r"/(udp|rtp)/(\d+\.\d+\.\d+\.\d+):(\d+)", path)
        if m:
            self._relay(m.group(2), int(m.group(3)))
            return

        logo_m = re.match(r"/logo/(.+\.(?:jpg|png|gif|webp))", path)
        if logo_m:
            self._logo(logo_m.group(1))
            return

        routes = {
            "": self._index, "/": self._index,
            "/status": self._status, "/stat": self._status,
            "/channels": self._channels,
            "/guide.xml": self._guide, "/epg.xml": self._guide,
            "/guide.xml.gz": self._guide_gz, "/epg.xml.gz": self._guide_gz,
        }
        handler = routes.get(path)
        if handler:
            handler()
        else:
            self.send_error(404)

    def _respond(self, code, body, ctype):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _index(self):
        body = (
            "<html><head><title>Movistar IPTV Relay</title></head><body>"
            "<h2>Movistar IPTV Relay v1.0.9</h2>"
            "<p>Uso: <code>/udp/239.x.x.x:8208/</code></p>"
            "<p><a href='/channels'>Canales</a> | "
            "<a href='/guide.xml'>EPG (XMLTV)</a> | "
            "<a href='/logo/5338.jpg'>Logo test</a> | "
            "<a href='/status'>Estado</a></p>"
            "</body></html>"
        )
        self._respond(200, body, "text/html")

    def _status(self):
        self._respond(200, json.dumps(self.state.status(), indent=2),
                      "application/json")

    def _channels(self):
        channels = self.state.get_channels()
        if not channels:
            self.send_error(503, "Discovery not complete yet")
            return
        host = self.headers.get("Host", "localhost:4022")
        base = f"http://{host}/logo/"
        enriched = {}
        for k, v in channels.items():
            ch = dict(v)
            logo = ch.get("logo", "")
            if logo and not logo.startswith("http"):
                ch["logo"] = base + logo
            enriched[str(k)] = ch
        out = {"data": {"channels": enriched}}
        self._respond(200, json.dumps(out, ensure_ascii=False, indent=2),
                      "application/json")

    def _guide(self):
        xmltv = self.state.get_xmltv()
        if not xmltv:
            self.send_error(503, "EPG not available yet")
            return
        ae = self.headers.get("Accept-Encoding", "")
        if "gzip" in ae:
            body = self.state.get_xmltv_gz()
            self.send_response(200)
            self.send_header("Content-Type", "application/xml; charset=utf-8")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        else:
            self._respond(200, xmltv, "application/xml; charset=utf-8")

    def _logo(self, filename):
        result = self.state.get_logo(filename)
        if not result:
            self.send_error(404, "Logo not found")
            return
        data, ctype = result
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=86400")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _guide_gz(self):
        gz = self.state.get_xmltv_gz()
        if not gz:
            self.send_error(503, "EPG not available yet")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/gzip")
        self.send_header("Content-Length", str(len(gz)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(gz)

    def _relay(self, addr, port):
        key = f"{addr}:{port}"
        state = self.state

        active = sum(len(v) for v in state.active.values())
        if active >= self.max_clients:
            self.send_error(503, "Max clients reached")
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_kb * 1024)
            sock.settimeout(10)
            sock.bind(("", port))
            mreq = struct.pack("4s4s",
                               socket.inet_aton(addr),
                               socket.inet_aton(self.interface))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError as e:
            self.send_error(503, f"Multicast join failed: {e}")
            return

        client = f"{self.client_address[0]}:{self.client_address[1]}"
        state.connect(key, client)
        print(f"[relay] + {client} -> {key}", flush=True)

        self.send_response(200)
        self.send_header("Content-Type", "video/MP2T")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Connection", "close")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        try:
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        total_bytes = 0
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
                    total_bytes += len(buf)
                    buf.clear()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            state.disconnect(key, client)
            state.add_bytes(total_bytes)
            print(f"[relay] - {client} -x {key} ({total_bytes // 1024} KB)", flush=True)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
            except OSError:
                pass
            sock.close()


# ── Background discovery ─────────────────────────────────────────────────────

class DiscoveryThread(threading.Thread):
    def __init__(self, state, iptv_ip, interval=3600):
        super().__init__(daemon=True, name="discovery")
        self.state = state
        self.iptv_ip = iptv_ip
        self.interval = interval
        self._epg_thread = None

    def run(self):
        while True:
            try:
                channels, segments, endpoint, logo_base = discover_channels(self.iptv_ip)
                if logo_base:
                    self.state.logo_base = logo_base
                if not channels:
                    print("[discovery] No channels found", flush=True)
                    time.sleep(self.interval)
                    continue
                self.state.set_channels(channels)
                try:
                    with open("/data/channels_cache.json", "w") as f:
                        json.dump(
                            {str(k): v for k, v in channels.items()},
                            f, ensure_ascii=False)
                except Exception:
                    pass

                if self._epg_thread is None or not self._epg_thread.is_alive():
                    self._epg_thread = EPGThread(
                        self.state, self.iptv_ip, channels, segments, endpoint)
                    self._epg_thread.start()

            except Exception as e:
                print(f"[discovery] Error: {e}", flush=True)

            time.sleep(self.interval)


class EPGThread(threading.Thread):
    def __init__(self, state, iptv_ip, channels, segments, endpoint):
        super().__init__(daemon=True, name="epg")
        self.state = state
        self.iptv_ip = iptv_ip
        self.channels = channels
        self.segments = segments
        self.endpoint = endpoint

    def run(self):
        try:
            epg = {}
            if self.segments:
                print(f"[epg] Downloading binary EPG ({len(self.segments)} segments)...",
                      flush=True)
                epg = download_epg_binary(self.segments, self.iptv_ip, self.channels)

            if len(epg) < len(self.channels) // 2 and self.endpoint:
                print(f"[epg] Binary EPG covers {len(epg)}/{len(self.channels)} channels, "
                      f"fetching rest from API...", flush=True)
                api_epg = download_epg_from_api(self.endpoint, self.channels)
                for ch_id, progs in api_epg.items():
                    if ch_id not in epg:
                        epg[ch_id] = progs
                    else:
                        epg[ch_id].update(progs)

            if epg:
                self.state.set_epg(epg, self.channels)
            else:
                print("[epg] No EPG data obtained", flush=True)

        except Exception as e:
            print(f"[epg] Error: {e}", flush=True)


# ── Main ─────────────────────────────────────────────────────────────────────

class ThreadedHTTPServer(HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def process_request(self, request, client_address):
        t = threading.Thread(target=self.process_request_thread,
                             args=(request, client_address), daemon=True)
        t.start()

    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


def load_ha_options():
    try:
        with open("/data/options.json") as f:
            return json.load(f)
    except FileNotFoundError:
        print("[relay] ERROR: /data/options.json not found", flush=True)
        sys.exit(1)


def main():
    p = argparse.ArgumentParser(description="Movistar IPTV Multicast-to-HTTP Relay")
    p.add_argument("--port", type=int, default=4022)
    p.add_argument("--interface", default="auto")
    p.add_argument("--max-clients", type=int, default=10)
    p.add_argument("--buffer", type=int, default=1024)
    p.add_argument("--ha-addon", action="store_true")
    args = p.parse_args()

    if args.ha_addon:
        opts = load_ha_options()
        args.port = int(opts.get("port", 4022))
        args.interface = opts.get("mcast_interface", "auto")
        args.max_clients = int(opts.get("max_clients", 10))
        args.buffer = int(opts.get("buffer_kb", 1024))

    if args.interface == "auto":
        iface = detect_iptv_ip()
        if not iface:
            print("[relay] ERROR: No se detecta la red IPTV de Movistar", flush=True)
            print("[relay] Configura mcast_interface manualmente", flush=True)
            sys.exit(1)
        print(f"[relay] Auto-detected IPTV interface: {iface}", flush=True)
    else:
        iface = args.interface
        print(f"[relay] Using configured interface: {iface}", flush=True)

    state = RelayState()

    # Load cached channels and EPG if available
    try:
        with open("/data/channels_cache.json") as f:
            cached = json.load(f)
        channels_cache = {int(k): v for k, v in cached.items()}
        state.set_channels(channels_cache)
        print(f"[relay] Loaded {len(cached)} cached channels", flush=True)
        try:
            with open("/data/epg_cache.json") as f:
                epg_cached = json.load(f)
            epg_data = {int(k): v for k, v in epg_cached.items()}
            if epg_data:
                state.set_epg(epg_data, channels_cache)
                print(f"[relay] Loaded cached EPG: {len(epg_data)} channels", flush=True)
        except Exception:
            pass
    except Exception:
        pass

    # Start background discovery
    discovery = DiscoveryThread(state, iface, interval=3600)
    discovery.start()
    print("[relay] Channel discovery started in background", flush=True)

    RelayHandler.interface = iface
    RelayHandler.buffer_kb = args.buffer
    RelayHandler.max_clients = args.max_clients
    RelayHandler.state = state

    server = ThreadedHTTPServer(("0.0.0.0", args.port), RelayHandler)

    print(f"[relay] Movistar IPTV Relay v1.0.9", flush=True)
    print(f"[relay] Listening on 0.0.0.0:{args.port}", flush=True)
    print(f"[relay] Multicast interface: {iface}", flush=True)
    print(f"[relay] Endpoints:", flush=True)
    print(f"[relay]   /udp/239.x.x.x:8208/  Stream", flush=True)
    print(f"[relay]   /channels              Channel list", flush=True)
    print(f"[relay]   /guide.xml             EPG (XMLTV)", flush=True)
    print(f"[relay]   /logo/<file>.jpg        Channel logo proxy", flush=True)
    print(f"[relay]   /status                Status", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[relay] Stopping...", flush=True)
        server.shutdown()


if __name__ == "__main__":
    main()
