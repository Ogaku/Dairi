import hashlib
import html as html_module
from html.parser import HTMLParser
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
import requests

_eduvulcan_sessions = {}


def solve_vulcan_pow(challenge: str, difficulty: int, rounds: int) -> str:
    if rounds <= 0:
        return ""
    results = []
    for _ in range(rounds):
        prefix = challenge + "".join(str(x) for x in results)
        nonce = 1
        while True:
            digest = hashlib.sha256((prefix + str(nonce)).encode('ascii')).digest()
            val = int.from_bytes(digest[:4], 'big', signed=False)
            if val < difficulty:
                results.append(nonce)
                break
            nonce += 1
    return ";".join(str(x) for x in results)


class WSFedFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None
        self.fields = {}

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag.lower() == 'form' and self.action is None:
            self.action = d.get('action')
        elif tag.lower() == 'input' and 'name' in d:
            self.fields[d['name']] = d.get('value', '')


def follow_wsfed_sso(session: requests.Session, start_url: str):
    r = session.get(start_url, allow_redirects=True, timeout=20)
    print(f"[sso] start {start_url} -> {r.status_code} url={r.url}", flush=True)
    for step in range(8):
        if r.status_code == 200 and ('<form' in r.text.lower() and ('wresult' in r.text.lower() or 'wa' in r.text.lower())):
            parser = WSFedFormParser()
            parser.feed(r.text)
            if not parser.action:
                print("[sso] No form action found", flush=True)
                break
            action = html_module.unescape(parser.action)
            form_data = {k: html_module.unescape(v) for k, v in parser.fields.items()}
            print(f"[sso] step {step}: POST to {action} with fields {list(form_data.keys())}", flush=True)
            for k, v in form_data.items():
                print(f"[sso] field {k}: len={len(v)} preview={v[:60]!r}", flush=True)
            r = session.post(action, data=form_data, allow_redirects=True, timeout=20)
            print(f"[sso] step {step} result: {r.status_code} url={r.url} body_len={len(r.text)}", flush=True)
        else:
            print(f"[sso] loop break: status={r.status_code} has_form={'<form' in r.text.lower()}", flush=True)
            break
    return r


def ensure_wiadomosci_sso(session: requests.Session, partition: str):
    if not partition:
        return False
    session.headers.update({
        'Accept': 'application/json, text/plain, */*',
        'Referer': f'https://wiadomosci.eduvulcan.pl/{partition}/App/odebrane',
    })
    test_url = f"https://wiadomosci.eduvulcan.pl/{partition}/api/Odebrane?idLastWiadomosc=0&pageSize=1"
    try:
        r = session.get(test_url, timeout=10, allow_redirects=False)
        if r.status_code == 200:
            return True
    except Exception:
        pass

    start_url = f"https://wiadomosci.eduvulcan.pl/{partition}/Account/Login"
    follow_wsfed_sso(session, start_url)

    try:
        app_url = f"https://wiadomosci.eduvulcan.pl/{partition}/App/odebrane"
        r_app = session.get(app_url, timeout=15, allow_redirects=True)
        print(f"[sso] visited {app_url} -> {r_app.status_code} url={r_app.url}", flush=True)
    except Exception as e:
        print(f"[sso] app visit error: {e}", flush=True)

    try:
        r = session.get(test_url, timeout=10, allow_redirects=False)
        sample_b = r.text[:200].encode('ascii', errors='backslashreplace').decode('ascii')
        print(f"[sso] final test_url {test_url} -> {r.status_code} body={sample_b!r}", flush=True)
        return r.status_code == 200
    except Exception as e:
        print(f"[sso] final test error: {e}", flush=True)
        return False


def handle_eduvulcan_login(login: str, password: str):
    s = requests.Session()
    s.headers['User-Agent'] = (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
    )

    login_url = 'https://eduvulcan.pl/logowanie?ReturnUrl=%2fapi%2fap'
    r1 = s.get(login_url, timeout=20)
    html1 = r1.text

    csrf_match = (
        re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', html1)
        or re.search(r'value="([^"]+)"[^>]*name="__RequestVerificationToken"', html1)
    )
    if not csrf_match:
        return {"error": "Failed to extract CSRF token from eduvulcan.pl/logowanie"}, 500
    csrf_token = csrf_match.group(1)

    show_captcha = True
    try:
        r2 = s.post(
            'https://eduvulcan.pl/Account/QueryUserInfo',
            data={'alias': login, '__RequestVerificationToken': csrf_token},
            timeout=15,
        )
        info = r2.json()
        if isinstance(info.get('data'), dict):
            show_captcha = bool(info['data'].get('ShowCaptcha', True))
    except Exception:
        show_captcha = True

    captcha_response = ''
    if show_captcha:
        ch_m = re.search(r'data-challenge="([^"]+)"', html1)
        df_m = re.search(r'data-difficulty="(\d+)"', html1)
        rd_m = re.search(r'data-rounds="(\d+)"', html1)
        if ch_m and df_m and rd_m:
            captcha_response = solve_vulcan_pow(
                ch_m.group(1),
                int(df_m.group(1)),
                int(rd_m.group(1)),
            )

    r3 = s.post(
        login_url,
        data={
            'Alias': login, 'UserName': login,
            'Password': password,
            'captcha-response': captcha_response,
            '__RequestVerificationToken': csrf_token,
        },
        allow_redirects=True,
        timeout=25,
    )

    body3 = r3.text
    if 'id="ap"' in body3 or "id='ap'" in body3 or '"Tokens"' in body3:
        _eduvulcan_sessions[login] = s
        return {"status": 200, "data": {"text": body3}}, 200

    if 'id="form1"' in body3 or '/logowanie' in r3.url:
        err_msgs = []
        for m in re.finditer(r'<div[^>]*class="[^"]*message-error[^"]*"[^>]*>([\s\S]*?)</div>', body3):
            cleaned = re.sub(r'<[^>]+>', ' ', m.group(1))
            cleaned = re.sub(r'\s+', ' ', cleaned).strip()
            if cleaned:
                err_msgs.append(cleaned)
        err_text = err_msgs[0] if err_msgs else "Nieprawidłowy login lub hasło eduVULCAN."
        return {"status": 401, "error": err_text, "data": {"error": err_text}}, 401

    r4 = s.get('https://eduvulcan.pl/api/ap', allow_redirects=True, timeout=20)
    body4 = r4.text
    if 'IsConsentAccepted":false' in body4.replace(' ', '') or "IsConsentAccepted':False" in body4.replace(' ', ''):
        try:
            s.post('https://eduvulcan.pl/konto/zgody', data={'Consent[0].Value': 'true', '__RequestVerificationToken': csrf_token}, timeout=15)
            r4 = s.get('https://eduvulcan.pl/api/ap', allow_redirects=True, timeout=20)
        except Exception:
            pass
    if r4.status_code == 200:
        _eduvulcan_sessions[login] = s
    return {"status": r4.status_code, "data": {"text": r4.text}}, r4.status_code


def handle_proxy_request(data):
    if not data or not isinstance(data, dict):
        return {"error": "Invalid JSON data"}, 400

    action = data.get('action')
    if action == 'eduvulcan_pow':
        solved = solve_vulcan_pow(
            str(data.get('challenge', '')),
            int(data.get('difficulty', 100000)),
            int(data.get('rounds', 15)),
        )
        return {"status": 200, "data": {"captcha": solved}}, 200

    if action == 'eduvulcan_login':
        return handle_eduvulcan_login(
            str(data.get('login', '')),
            str(data.get('password', '')),
        )

    if action == 'eduvulcan_fetch_messages':
        login = str(data.get('login', ''))
        password = str(data.get('password', ''))
        partition = str(data.get('partition', ''))
        folder = str(data.get('folder', 'Odebrane'))
        page_size = int(data.get('pageSize', 50))
        id_last = int(data.get('idLastWiadomosc', 0))

        print(f"[proxy] eduvulcan_fetch_messages: login={login!r}, has_password={bool(password)}, partition={partition!r}", flush=True)

        s = _eduvulcan_sessions.get(login)
        if not s and password:
            print(f"[proxy] Session not in cache, attempting handle_eduvulcan_login for {login!r}...", flush=True)
            res, code = handle_eduvulcan_login(login, password)
            print(f"[proxy] handle_eduvulcan_login returned code={code}", flush=True)
            s = _eduvulcan_sessions.get(login)

        if not s:
            if len(_eduvulcan_sessions) == 1:
                s = next(iter(_eduvulcan_sessions.values()))
            else:
                print(f"[proxy] Error: No active session for {login!r}", flush=True)
                return {"error": "Brak aktywnej sesji eduVULCAN w proxy"}, 401

        ok = ensure_wiadomosci_sso(s, partition)
        print(f"[proxy] ensure_wiadomosci_sso for {partition} -> {ok}", flush=True)

        url = f"https://wiadomosci.eduvulcan.pl/{partition}/api/{folder}?idLastWiadomosc={id_last}&pageSize={page_size}"
        r = s.get(url, timeout=15)
        try:
            return {"status": 200, "data": r.json()}, 200
        except Exception:
            return {"status": r.status_code, "data": {"text": r.text}}, r.status_code

    if action == 'eduvulcan_fetch_message_content':
        login = str(data.get('login', ''))
        partition = str(data.get('partition', ''))
        msg_id = data.get('id')
        global_key = data.get('apiGlobalKey')

        s = _eduvulcan_sessions.get(login)
        if not s and 'password' in data and data['password']:
            handle_eduvulcan_login(login, str(data['password']))
            s = _eduvulcan_sessions.get(login)

        if not s:
            if len(_eduvulcan_sessions) == 1:
                s = next(iter(_eduvulcan_sessions.values()))
            else:
                return {"error": "Brak aktywnej sesji eduVULCAN w proxy"}, 401

        ensure_wiadomosci_sso(s, partition)
        urls_to_try = [
            f"https://wiadomosci.eduvulcan.pl/{partition}/api/WiadomoscSzczegoly?id={msg_id}",
            f"https://wiadomosci.eduvulcan.pl/{partition}/api/Wiadomosc?id={msg_id}",
            f"https://wiadomosci.eduvulcan.pl/{partition}/api/WiadomoscSzczegoly?apiGlobalKey={global_key}",
            f"https://wiadomosci.eduvulcan.pl/{partition}/api/Wiadomosc?apiGlobalKey={global_key}",
        ]
        for url in urls_to_try:
            if msg_id is None and 'id=' in url:
                continue
            if not global_key and 'apiGlobalKey=' in url:
                continue
            r = s.get(url, timeout=15)
            if r.status_code == 200:
                try:
                    return {"status": 200, "data": r.json()}, 200
                except Exception:
                    pass
        return {"status": 404, "error": "Nie znaleziono tresci wiadomosci"}, 404

    url = data.get('uri')
    if not url:
        return {"error": "Missing 'uri' in request data"}, 400

    headers = dict(data.get('headers') or {})
    request_options = {
        'headers': headers,
        'allow_redirects': True,
    }

    if 'query' in data and data['query']:
        url = requests.Request('GET', url, params=data['query']).prepare().url

    session = requests.Session()
    initial_host = urlparse(url).hostname

    if 'cookies' in data and isinstance(data['cookies'], dict):
        for k, v in data['cookies'].items():
            if initial_host:
                session.cookies.set(str(k), str(v), domain=initial_host)
            else:
                session.cookies.set(str(k), str(v))

    if 'data' in data and data['data'] is not None:
        content_type = headers.get('Content-Type') or headers.get('content-type') or ''
        if 'application/json' in content_type and not isinstance(data['data'], (str, bytes)):
            request_options['data'] = json.dumps(data['data'])
        else:
            request_options['data'] = data['data']

    response = session.request(method=data.get('method', 'GET'), url=url, **request_options)

    out_cookies = dict(data.get('cookies') or {}) if isinstance(data.get('cookies'), dict) else {}
    for c in session.cookies:
        out_cookies[c.name] = c.value
    for hist_resp in response.history:
        for c in hist_resp.cookies:
            out_cookies[c.name] = c.value
    for c in response.cookies:
        out_cookies[c.name] = c.value

    try:
        parsed_body = response.json() if 'application/json' in response.headers.get('Content-Type', '') else {"text": response.text}
    except Exception:
        parsed_body = {"text": response.text}

    try:
        sample = response.text[:300].replace('\n', ' ').encode('ascii', errors='backslashreplace').decode('ascii')
        print(f'[proxy] {data.get("method", "GET")} {url} -> {response.status_code} | {sample}', flush=True)
        if isinstance(parsed_body, dict) and 'Envelope' in parsed_body:
            env = parsed_body['Envelope']
            if isinstance(env, list) and len(env) > 0 and isinstance(env[0], dict):
                print(f'[proxy-sample] {url} -> item keys: {list(env[0].keys())}', flush=True)
                sample_item = json.dumps(env[0], ensure_ascii=False)
                print(f'[proxy-sample] item 0: {sample_item[:600]}', flush=True)
    except Exception:
        pass

    response_data = {
        "status": response.status_code,
        "headers": dict(response.headers),
        "cookies": out_cookies,
        "data": parsed_body,
    }

    return response_data, response.status_code


try:
    from flask import Flask, jsonify, request  # type: ignore
    from flask_cors import CORS, cross_origin  # type: ignore

    app = Flask(__name__)
    cors = CORS(app, supports_credentials=True)
    app.config['CORS_HEADERS'] = 'Content-Type'

    @app.route("/", methods=["GET", "POST", "OPTIONS"])
    @cross_origin(supports_credentials=True)
    def proxy():
        if request.method == "GET":
            return jsonify({"status": "ok", "service": "Dairi CORS Proxy for Oshi"}), 200
        body, status = handle_proxy_request(request.get_json(force=True, silent=True))
        return jsonify(body), status
except ImportError:
    app = None


class DairiHTTPRequestHandler(BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        origin = self.headers.get('Origin') or '*'
        self.send_header('Access-Control-Allow-Origin', origin)
        self.send_header('Access-Control-Allow-Credentials', 'true')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        req_headers = self.headers.get('Access-Control-Request-Headers') or 'Content-Type, Authorization, X-Requested-With'
        self.send_header('Access-Control-Allow-Headers', req_headers)

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        payload = json.dumps({"status": "ok", "service": "Dairi CORS Proxy for Oshi"}).encode('utf-8')
        self.send_response(200)
        self._send_cors_headers()
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length') or 0)
            raw = self.rfile.read(length).decode('utf-8') if length > 0 else '{}'
            data = json.loads(raw)
            body, status = handle_proxy_request(data)
        except Exception as ex:
            body, status = {"error": str(ex)}, 500

        payload = json.dumps(body).encode('utf-8')
        self.send_response(status)
        self._send_cors_headers()
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == '__main__':
    server = ThreadingHTTPServer(('127.0.0.1', 5000), DairiHTTPRequestHandler)
    print('Dairi CORS proxy listening on http://127.0.0.1:5000', flush=True)
    server.serve_forever()
