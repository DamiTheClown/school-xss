import hashlib
import os
from flask import Flask, request, render_template, make_response, send_file, redirect, url_for
from markupsafe import escape  # OPRAVA: Funkce pro zneškodnění HTML tagů

app = Flask(__name__)
all_messages = {}

ADMIN_USER = os.getenv('ADMIN_USER', 'superuser_fake')
ADMIN_PASS = os.getenv('ADMIN_PASS', 'superpassword_fake')
ADMIN_TOKEN = os.getenv('ADMIN_TOKEN', 'supertoken_fake')

@app.route('/')
def index():
    auth_token = request.cookies.get('auth_session')
    student_ip = request.remote_addr
    flag_hash = hashlib.sha256(student_ip.encode()).hexdigest()[:12].upper()
    unique_flag = f"CTF{{XSS_MASTER_{flag_hash}}}"
    is_admin = (auth_token == ADMIN_TOKEN)

    msghtml = ""
    waiting_count = 0
    for msg_id in sorted(all_messages.keys(), reverse=True):
        msg_data = all_messages[msg_id]
        if not msg_data['reviewed']:
            waiting_count += 1

        if is_admin or msg_data['ip'] == student_ip:
            status = "⏳ Čeká" if not msg_data['reviewed'] else "✅ OK"
            color = "#fff3cd" if not msg_data['reviewed'] else "#d4edda"

            # OPRAVA XSS: escape() změní <script> na prostý text, který se nespustí.
            # PŮVODNĚ: {msg_data["content"]} (vkládalo surový kód přímo do HTML)
            safe_content = escape(msg_data["content"])

            msghtml += f'''
            <div style="border: 1px solid #ccc; padding: 10px; margin: 10px 0; background: {color};">
                <strong>Vzkaz #{msg_id}</strong> - {status}<br>
                <div style="padding: 5px; background: rgba(255,255,255,0.5);">{safe_content}</div>
            </div>
            '''
    
    return render_template('index.html', is_admin=is_admin, flag=unique_flag, msghtml=msghtml, queue_info=f"Fronta: {waiting_count}")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('username') == ADMIN_USER and request.form.get('password') == ADMIN_PASS:
            resp = make_response(redirect(url_for('index')))
            # OPRAVA HIJACKINGU: httponly=True zakáže JavaScriptu přístup k cookie.
            # PŮVODNĚ: httponly=False (umožňovalo krádež session přes document.cookie)
            resp.set_cookie('auth_session', ADMIN_TOKEN, httponly=True, samesite='Lax')
            return resp
        return "Chyba!", 401
    return '...Login Form...' # (zde by byl tvůj HTML formulář)

@app.route('/post', methods=['POST'])
def post():
    content = request.form.get('content', '')
    if content and len(content) <= 2000:
        msg_id = len(all_messages) + 1
        all_messages[msg_id] = {"ip": request.remote_addr, "content": content, "reviewed": False}
    return 'Odesláno. <a href="/">Zpět</a>'

@app.route('/admin/view/<int:msg_id>')
def admin_view(msg_id):
    if request.cookies.get('auth_session') != ADMIN_TOKEN: return "403", 403
    msg = all_messages.get(msg_id)
    if not msg: return "404", 404
    msg['reviewed'] = True
    # OPRAVA XSS: Escapujeme i v náhledu pro admina.
    return f"<html><body><h1>Vzkaz {msg_id}</h1>{escape(msg['content'])}</body></html>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
