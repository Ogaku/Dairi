import hashlib
import html as html_module
from html.parser import HTMLParser
import json
import re
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.parse
from urllib.parse import urlparse, quote
import requests

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

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


_prometheus_tokens = {}


def submit_form_if_present(session, resp, label="sso"):
    curr = resp
    for step in range(5):
        if not curr:
            print(f"[{label}] (step {step+1}) curr is None", flush=True)
            break
        try:
            with open(f"A:\\Documents\\repos\\Dairi\\debug_{label}_step_{step}.html", "w", encoding="utf-8") as f:
                f.write(f"<!-- URL: {curr.url} STATUS: {curr.status_code} -->\n" + curr.text)
        except Exception:
            pass
        if '<form' not in curr.text.lower():
            print(f"[{label}] (step {step+1}) No '<form' in body. status={curr.status_code} url={curr.url} (body_len={len(curr.text)})", flush=True)
            break
        parser = WSFedFormParser()
        parser.feed(curr.text)
        action = urllib.parse.urljoin(curr.url, parser.action or curr.url)
        form_data = parser.fields
        print(f"[{label}] (step {step+1}) submit_form to {action} with fields {list(form_data.keys())}", flush=True)
        curr = session.post(action, data=form_data, timeout=25, allow_redirects=True)
        print(f"[{label}] (step {step+1}) submitted -> {curr.status_code} {curr.url} (body_len={len(curr.text)})", flush=True)
    return curr


def authorize_prometheus(session, url, label="flow"):
    html_headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Upgrade-Insecure-Requests': '1',
    }
    r1 = session.get(url, headers=html_headers, timeout=25, allow_redirects=True)
    print(f"[{label}] authorize GET {url[:100]}... -> {r1.status_code} {r1.url}", flush=True)
    return submit_form_if_present(session, r1, label=label)


def ensure_prometheus_messages_session(session: requests.Session, tenant: str):
    if not tenant:
        return None

    cached = _prometheus_tokens.get(tenant)
    if cached and cached.get('appGuid') and cached.get('antiForgeryToken'):
        return cached

    sso_base = "https://dziennik-logowanie.vulcan.net.pl"
    messages_base = "https://wiadomosci.eduvulcan.pl"
    prometheus_encoded = urllib.parse.quote("https://eduvulcan.pl", safe="")
    sso_encoded = urllib.parse.quote(sso_base, safe="")
    student_encoded = urllib.parse.quote("https://uczen.eduvulcan.pl", safe="")

    # Flow 1: Authenticate client in the SSO domain via uczen.eduvulcan.pl
    first_auth_url = (
        f"https://eduvulcan.pl/fs/ls?wa=wsignin1.0&wtrealm={sso_encoded}%2F{tenant}%2FFs%2FLs"
        f"%3Fwa%3Dwsignin1.0%26wtrealm%3D{student_encoded}%2F{tenant}%2FAccount%2FLogin"
        f"%3FreturnUrl%3D{prometheus_encoded}%26wctx%3Dauth%3DstudentEV%26nslo%3D1&wctx=nslo%3D1"
    )
    print(f"[sso] Prometheus Flow 1: firstAuthUrl for tenant={tenant}", flush=True)
    authorize_prometheus(session, first_auth_url, label="flow1")

    # Flow 2: Authenticate client in the messages domain
    authorize_url = (
        f"{sso_base}/{tenant}/Fs/Ls?wa=wsignin1.0&wtrealm={messages_base}/{tenant}/Account/Login"
        f"?returnUrl=/{tenant}/App&wctx=auth=studentEV&nslo=1"
    )
    print(f"[sso] Prometheus Flow 2: authorizeUrl for tenant={tenant}", flush=True)
    authorize_prometheus(session, authorize_url, label="flow2")

    # Step 4: Fetch tokens from App
    app_url = f"{messages_base}/{tenant}/App"
    print(f"[sso] Fetching tokens from {app_url}", flush=True)
    r_app = session.get(app_url, timeout=20, allow_redirects=True)
    if '<form' in r_app.text.lower():
        r_app = submit_form_if_present(session, r_app, label="app_auth")
    try:
        with open("A:\\Documents\\repos\\Dairi\\debug_app.html", "w", encoding="utf-8") as f:
            f.write(f"<!-- URL: {r_app.url} STATUS: {r_app.status_code} -->\n" + r_app.text)
    except Exception:
        pass
    anti_m = re.search(r"""antiForgeryToken:\s*['"]([^'"]+)['"]""", r_app.text)
    guid_m = re.search(r"""appGuid:\s*['"]([^'"]+)['"]""", r_app.text)
    anti_forgery_token = anti_m.group(1) if anti_m else ""
    app_guid = guid_m.group(1) if guid_m else ""

    print(f"[sso] Extracted antiForgeryToken={'OK' if anti_forgery_token else 'EMPTY'}, appGuid={'OK' if app_guid else 'EMPTY'}", flush=True)
    if not (anti_forgery_token and app_guid):
        print(f"[sso] Failed to extract tokens! status={r_app.status_code} url={r_app.url} len={len(r_app.text)}", flush=True)

    if anti_forgery_token and app_guid:
        res = {'appGuid': app_guid, 'antiForgeryToken': anti_forgery_token}
        _prometheus_tokens[tenant] = res
        return res
    return None


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

        mailbox_key = data.get('mailboxKey') or data.get('boxKey')
        print(f"[proxy] eduvulcan_fetch_messages: login={login!r}, partition={partition!r}, folder={folder!r}, mailboxKey={mailbox_key!r}", flush=True)

        try:
            tokens = ensure_prometheus_messages_session(s, partition)
            if not tokens:
                print(f"[proxy] Error: Failed to obtain Prometheus messages tokens for {partition}", flush=True)
                return {"error": "Nie udalo sie pobrac tokenow do wiadomosci (Prometheus SSO)"}, 500

            api_headers = {
                'X-V-AppGuid': tokens['appGuid'],
                'X-V-RequestVerificationToken': tokens['antiForgeryToken'],
                'Content-Type': 'application/json',
                'Accept': 'application/json, text/plain, */*',
                'Referer': f"https://wiadomosci.eduvulcan.pl/{partition}/App",
            }

            # If mailbox_key was not provided, fetch /api/Skrzynki to discover it
            if not mailbox_key:
                try:
                    r_boxes = s.get(f"https://wiadomosci.eduvulcan.pl/{partition}/api/Skrzynki", headers=api_headers, timeout=15)
                    boxes = r_boxes.json()
                    print(f"[proxy] /api/Skrzynki returned: {boxes}", flush=True)
                    if isinstance(boxes, list) and boxes:
                        mailbox_key = boxes[0].get('globalKey')
                except Exception as e:
                    print(f"[proxy] Failed to fetch /api/Skrzynki: {e}", flush=True)

            if folder.lower() in ('wyslane', 'sent'):
                endpoint = '/api/WyslaneSkrzynka'
            elif folder.lower() in ('usuniete', 'deleted'):
                endpoint = '/api/UsunieteSkrzynka'
            else:
                endpoint = '/api/OdebraneSkrzynka'

            url = f"https://wiadomosci.eduvulcan.pl/{partition}{endpoint}"
            params = {
                'idLastWiadomosc': id_last,
                'pageSize': page_size,
            }
            if mailbox_key:
                params['globalKeySkrzynka'] = mailbox_key

            r = s.get(url, params=params, headers=api_headers, timeout=15)
            print(f"[proxy] {endpoint} status={r.status_code} body_len={len(r.text)}", flush=True)

            r_json = None
            try:
                r_json = r.json()
            except Exception:
                pass

            is_error = (r.status_code in (401, 403, 409)) or (isinstance(r_json, dict) and ('message' in r_json or 'error' in r_json))
            if is_error:
                print(f"[proxy] {endpoint} unauthorized/error ({r.status_code}: {r_json}), re-authenticating SSO for {partition}...", flush=True)
                _prometheus_tokens.pop(partition, None)
                tokens = ensure_prometheus_messages_session(s, partition)
                if tokens:
                    api_headers['X-V-AppGuid'] = tokens['appGuid']
                    api_headers['X-V-RequestVerificationToken'] = tokens['antiForgeryToken']
                    r = s.get(url, params=params, headers=api_headers, timeout=15)
                    print(f"[proxy] {endpoint} retry status={r.status_code} body_len={len(r.text)}", flush=True)
                    try:
                        r_json = r.json()
                    except Exception:
                        pass

            if r.status_code == 200 and isinstance(r_json, (list, dict)):
                return {"status": 200, "data": r_json}, 200
            return {"status": r.status_code, "data": r_json or r.text}, (r.status_code if r.status_code != 200 else 401)
        except Exception as e:
            print(f"[proxy] Exception in eduvulcan_fetch_messages: {e}", flush=True)
            traceback.print_exc()
            return {"error": str(e)}, 500

    if action == 'eduvulcan_fetch_message_content':
        try:
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

            tokens = ensure_prometheus_messages_session(s, partition)
            if not tokens:
                return {"error": "Nie udalo sie pobrac tokenow do wiadomosci"}, 500

            api_headers = {
                'X-V-AppGuid': tokens['appGuid'],
                'X-V-RequestVerificationToken': tokens['antiForgeryToken'],
                'Content-Type': 'application/json',
                'Accept': 'application/json, text/plain, */*',
                'Referer': f"https://wiadomosci.eduvulcan.pl/{partition}/App",
            }

            url = f"https://wiadomosci.eduvulcan.pl/{partition}/api/WiadomoscSzczegoly"
            r = s.get(url, params={'apiGlobalKey': global_key or msg_id}, headers=api_headers, timeout=15)
            print(f"[proxy] /api/WiadomoscSzczegoly status={r.status_code} body_len={len(r.text)}", flush=True)

            r_json = None
            try:
                r_json = r.json()
            except Exception:
                pass

            is_error = (r.status_code in (401, 403, 409)) or (isinstance(r_json, dict) and ('message' in r_json or 'error' in r_json))
            if is_error:
                print(f"[proxy] /api/WiadomoscSzczegoly unauthorized/error ({r.status_code}: {r_json}), re-authenticating SSO for {partition}...", flush=True)
                _prometheus_tokens.pop(partition, None)
                tokens = ensure_prometheus_messages_session(s, partition)
                if tokens:
                    api_headers['X-V-AppGuid'] = tokens['appGuid']
                    api_headers['X-V-RequestVerificationToken'] = tokens['antiForgeryToken']
                    r = s.get(url, params={'apiGlobalKey': global_key or msg_id}, headers=api_headers, timeout=15)
                    print(f"[proxy] /api/WiadomoscSzczegoly retry status={r.status_code} body_len={len(r.text)}", flush=True)
                    try:
                        r_json = r.json()
                    except Exception:
                        pass

            if r.status_code == 200 and isinstance(r_json, dict):
                return {"status": 200, "data": r_json}, 200
            return {"status": r.status_code, "data": r_json or r.text}, (r.status_code if r.status_code != 200 else 401)
        except Exception as e:
            print(f"[proxy] Exception in eduvulcan_fetch_message_content: {e}", flush=True)
            traceback.print_exc()
            return {"error": str(e)}, 500

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
