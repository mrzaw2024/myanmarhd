#!/usr/bin/env python3
import os
import re
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
EXT_PROXY = "https://z317922-bh22ex.ls04.zwhhosting.com/proxy.php"
PORT = 8000
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
SUFFIX_START = 512 * 1024
SUFFIX_MAX = 4 * 1024 * 1024
HEAD_CHUNK = 65536

_info_cache = {}
_info_cache_lock = threading.Lock()


def ext_url(target):
    return EXT_PROXY + "?url=" + urllib.parse.quote(target, safe="")


def open_ext(target, range_hdr=None):
    headers = {"User-Agent": USER_AGENT}
    if range_hdr:
        headers["Range"] = range_hdr
    req = urllib.request.Request(ext_url(target), headers=headers)
    return urllib.request.urlopen(req, timeout=30)


def get_total(target):
    r = open_ext(target, "bytes=0-0")
    try:
        cr = r.headers.get("Content-Range", "")
        m = re.search(r"/(\d+)\s*$", cr)
        if m:
            return int(m.group(1))
        cl = r.headers.get("Content-Length")
        if cl:
            return int(cl)
    finally:
        r.close()
    return None


def get_head(target):
    r = open_ext(target, "bytes=0-{}".format(HEAD_CHUNK - 1))
    try:
        b = r.read()
    finally:
        r.close()
    off = 0
    while off + 8 <= len(b):
        size = int.from_bytes(b[off:off + 4], "big")
        typ = b[off + 4:off + 8].decode("latin1", "replace")
        if typ == "mdat":
            return off, b
        if size < 8:
            break
        off += size
    return 0, b


def get_head_len(target):
    off, _ = get_head(target)
    return off


def _find_moov_at_end(b, total):
    start = total - len(b)
    idx = 0
    while True:
        idx = b.find(b"moov", idx)
        if idx == -1:
            return None
        if idx >= 4:
            size = int.from_bytes(b[idx - 4:idx], "big")
            file_off = start + (idx - 4)
            if 8 <= size <= total and file_off + size == total:
                return file_off, size, bytes(b[idx - 4:idx - 4 + size])
        idx += 4


def get_moov(target, total):
    chunk = min(SUFFIX_MAX, total)
    while chunk >= 65536:
        start = total - chunk
        r = open_ext(target, "bytes={}-{}".format(start, total - 1))
        try:
            b = r.read()
        finally:
            r.close()
        found = _find_moov_at_end(b, total)
        if found:
            return found
        if chunk >= total:
            break
        chunk = min(chunk * 2, total)
    return None, None, None


CONTAINERS = {"moov", "trak", "mdia", "minf", "stbl", "edts", "dinf",
              "mvex", "udta", "tref", "mfra", "moof", "traf", "meco"}


def patch_moov(moov_bytes, shift):
    b = bytearray(moov_bytes)

    def walk(start, end):
        i = start
        while i + 8 <= end:
            size = int.from_bytes(b[i:i + 4], "big")
            typ = b[i + 4:i + 8].decode("latin1", "replace")
            if size < 8:
                break
            if typ == "stco":
                count = int.from_bytes(b[i + 12:i + 16], "big")
                for k in range(count):
                    off = i + 16 + k * 4
                    if off + 4 <= end:
                        val = int.from_bytes(b[off:off + 4], "big") + shift
                        b[off:off + 4] = val.to_bytes(4, "big")
            elif typ == "co64":
                count = int.from_bytes(b[i + 12:i + 16], "big")
                for k in range(count):
                    off = i + 16 + k * 8
                    if off + 8 <= end:
                        val = int.from_bytes(b[off:off + 8], "big") + shift
                        b[off:off + 8] = val.to_bytes(8, "big")
            elif typ in CONTAINERS:
                walk(i + 8, i + size)
            i += size

    walk(0, len(b))
    return bytes(b)


def _probe(target):
    result = {"total": None, "head": 0, "head_bytes": b"",
              "moff": None, "msize": None, "moov": None}

    def fetch_prefix():
        try:
            head, b = get_head(target)
            result["head"] = head
            result["head_bytes"] = b
        except Exception:
            pass

    def fetch_suffix():
        try:
            chunk = SUFFIX_START
            while chunk <= SUFFIX_MAX:
                r = open_ext(target, "bytes=-{}".format(chunk))
                try:
                    b = r.read()
                finally:
                    r.close()
                cr = r.headers.get("Content-Range", "")
                m = re.search(r"/(\d+)\s*$", cr)
                if not m:
                    return
                total = int(m.group(1))
                found = _find_moov_at_end(b, total)
                if found:
                    result["total"] = total
                    result["moff"], result["msize"], result["moov"] = found
                    return
                if chunk >= total:
                    break
                chunk = min(chunk * 2, SUFFIX_MAX)
        except Exception:
            pass

    t1 = threading.Thread(target=fetch_prefix)
    t2 = threading.Thread(target=fetch_suffix)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    if result["total"] is None or result["moff"] is None:
        total = result["total"] or get_total(target)
        if not total:
            return None
        if result["head"] == 0:
            try:
                result["head"], result["head_bytes"] = get_head(target)
            except Exception:
                pass
        moff, msize, moov_bytes = get_moov(target, total)
        if moff is None:
            return None
        return {"total": total, "head": result["head"],
                "head_bytes": result["head_bytes"], "moff": moff,
                "msize": msize, "moov": moov_bytes}
    return result


def get_info(target):
    now = time.time()
    with _info_cache_lock:
        cached = _info_cache.get(target)
        if cached and now - cached["ts"] < 1800:
            return cached
    try:
        probe = _probe(target)
        if not probe or probe["total"] is None or probe["moff"] is None:
            return None
        info = {"total": probe["total"], "head": probe["head"],
                "head_bytes": probe["head_bytes"],
                "moov_off": probe["moff"], "moov_size": probe["msize"],
                "moov": patch_moov(probe["moov"], probe["msize"]),
                "ts": now}
        with _info_cache_lock:
            _info_cache[target] = info
        return info
    except Exception:
        return None


def parse_range(hdr, total):
    m = re.match(r"bytes=(\d*)-(\d*)$", hdr.strip())
    if not m:
        return None
    s, e = m.group(1), m.group(2)
    if s == "" and e == "":
        return None
    if s == "":
        n = int(e)
        if n <= 0:
            return None
        return total - n, total - 1
    start = int(s)
    end = int(e) if e else total - 1
    end = min(end, total - 1)
    if start > end or start >= total:
        return None
    return start, end


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_HEAD(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/stream":
            qs = urllib.parse.parse_qs(parsed.query)
            target = (qs.get("url") or [None])[0]
            info = get_info(target) if target else None
            if not info:
                self.send_error(400)
                return
            total = info["total"]
            self.send_response(200)
            self.send_header("Content-Type", "video/mp4")
            self.send_header("Content-Length", str(total))
            self.send_header("Accept-Ranges", "bytes")
            self.end_headers()
            return
        self.serve_static(parsed.path, head=True)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/stream":
            qs = urllib.parse.parse_qs(parsed.query)
            target = (qs.get("url") or [None])[0]
            if not target:
                self.send_error(400)
                return
            self.stream_video(target)
            return
        self.serve_static(parsed.path, head=False)

    def serve_static(self, path, head=False):
        if path in ("/", ""):
            path = "/index.html"
        full = os.path.normpath(os.path.join(ROOT, path.lstrip("/")))
        if not full.startswith(ROOT) or not os.path.isfile(full):
            self.send_error(404)
            return
        with open(full, "rb") as f:
            data = f.read()
        ctype = "text/html" if full.endswith(".html") else "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if not head:
            self.wfile.write(data)

    def stream_video(self, target):
        info = get_info(target)
        if not info:
            self.proxy_passthrough(target)
            return
        total = info["total"]
        range_hdr = self.headers.get("Range")
        if not range_hdr:
            self.send_response(200)
            self.send_header("Content-Type", "video/mp4")
            self.send_header("Content-Length", str(total))
            self.send_header("Accept-Ranges", "bytes")
            self.end_headers()
            self.stream_fs_region(0, total - 1, target, info)
            return
        start, end = parse_range(range_hdr, total)
        if start is None:
            self.send_error(416)
            return
        self.send_response(206)
        self.send_header("Content-Type", "video/mp4")
        self.send_header("Content-Range", "bytes {}-{}/{}".format(start, end, total))
        self.send_header("Content-Length", str(end - start + 1))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()
        self.stream_fs_region(start, end, target, info)

    def stream_fs_region(self, fs_start, fs_end, target, info):
        H = info["head"]
        moff = info["moov_off"]
        msize = info["moov_size"]
        total = info["total"]
        head_bytes = info.get("head_bytes")
        regions = [
            (0, H - 1, 0, H - 1, "head" if head_bytes else None),
            (H, H + msize - 1, 0, msize - 1, "moov"),
            (H + msize, total - 1, H, moff - 1, None),
        ]
        for fs_a, fs_b, o_a, o_b, src in regions:
            a = max(fs_start, fs_a)
            b = min(fs_end, fs_b)
            if a > b:
                continue
            o_start = o_a + (a - fs_a)
            o_end = o_b - (fs_b - b)
            if src == "moov":
                if not self.write_bytes(info["moov"], o_start, o_end):
                    return
            elif src == "head":
                if not self.write_bytes(head_bytes, o_start, o_end):
                    return
            else:
                if not self.copy_range(target, o_start, o_end):
                    return

    def write_bytes(self, data, start, end):
        try:
            self.wfile.write(data[start:end + 1])
            self.wfile.flush()
        except Exception:
            return False
        return True

    def copy_range(self, target, o_start, o_end):
        try:
            r = open_ext(target, "bytes={}-{}".format(o_start, o_end))
        except Exception:
            return False
        try:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except Exception:
            return False
        finally:
            r.close()
        return True

    def proxy_passthrough(self, target):
        range_hdr = self.headers.get("Range")
        try:
            r = open_ext(target, range_hdr)
        except Exception:
            self.send_error(502)
            return
        try:
            self.send_response(r.status)
            self.send_header("Content-Type", r.headers.get("Content-Type", "video/mp4"))
            cl = r.headers.get("Content-Length")
            if cl:
                self.send_header("Content-Length", cl)
            cr = r.headers.get("Content-Range")
            if cr:
                self.send_header("Content-Range", cr)
            self.send_header("Accept-Ranges", "bytes")
            self.end_headers()
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except Exception:
            pass
        finally:
            r.close()


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("serving on 0.0.0.0:{}".format(PORT))
    server.serve_forever()
