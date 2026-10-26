#!/bin/bash
# LabShare - one-shot setup. Run on your EC2 Ubuntu server AFTER Hadoop is installed.
set -e

export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))
export HADOOP_HOME=/opt/hadoop
export PATH=$PATH:$HADOOP_HOME/bin:$HADOOP_HOME/sbin

echo "== 1/5 Checking HDFS =="
if ! jps | grep -q NameNode; then
  start-dfs.sh
  sleep 8
fi
jps
hdfs dfs -mkdir -p /labshare/files

echo "== 2/5 Creating project folder =="
mkdir -p ~/labshare/docs-site
cd ~/labshare

echo "== 3/5 Installing Python packages =="
python3 -m venv venv
./venv/bin/pip install -q flask cryptography

echo "== 4/5 Writing project files =="

cat > app.py <<'PYEOF'
import os, sqlite3, subprocess, shutil, tempfile, hashlib, uuid, io
from datetime import datetime
from flask import (Flask, request, redirect, url_for, session,
                   render_template_string, send_file, flash, abort)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.utils import secure_filename

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "labshare.db")
KEY_FILE = os.path.join(BASE, "secret.key")
HDFS_ROOT = "/labshare/files"
CHUNK = 1024 * 1024  # 1 MB application-level segments
ADMIN_PASSWORD = os.environ.get("LABSHARE_ADMIN_PASSWORD", "admin123")
HDFS_BIN = os.path.join(os.environ.get("HADOOP_HOME", "/opt/hadoop"), "bin", "hdfs")
ALLOWED = {"pdf", "doc", "docx", "ppt", "pptx", "xls", "xlsx", "txt", "zip",
           "png", "jpg", "jpeg", "mp4"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB limit


# ---------- helpers ----------
def get_key():
    """AES-256 key, created once and kept on the server."""
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(os.urandom(32))
        os.chmod(KEY_FILE, 0o600)
    with open(KEY_FILE, "rb") as f:
        return f.read()


app.secret_key = hashlib.sha256(get_key()).hexdigest()


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS files(
            id TEXT PRIMARY KEY, title TEXT, subject TEXT, filename TEXT,
            size INTEGER, enc_size INTEGER, chunks INTEGER,
            uploaded_at TEXT, downloads INTEGER DEFAULT 0)""")


def hdfs(*args):
    r = subprocess.run([HDFS_BIN, "dfs", *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr[-600:])
    return r.stdout


def encrypt(data):
    nonce = os.urandom(12)
    return nonce + AESGCM(get_key()).encrypt(nonce, data, None)


def decrypt(blob):
    return AESGCM(get_key()).decrypt(blob[:12], blob[12:], None)


def store_in_hdfs(file_id, enc):
    """Split encrypted bytes into 1 MB chunks and put them in HDFS."""
    tmp = tempfile.mkdtemp()
    try:
        paths = []
        for n, i in enumerate(range(0, len(enc), CHUNK)):
            p = os.path.join(tmp, "chunk_%04d" % n)
            with open(p, "wb") as f:
                f.write(enc[i:i + CHUNK])
            paths.append(p)
        d = f"{HDFS_ROOT}/{file_id}"
        hdfs("-mkdir", "-p", d)
        hdfs("-put", "-f", *paths, d + "/")
        return len(paths)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def load_from_hdfs(file_id, expected_size):
    """Fetch chunks from HDFS and join them in order."""
    tmp = tempfile.mkdtemp()
    try:
        hdfs("-get", f"{HDFS_ROOT}/{file_id}", tmp)
        d = os.path.join(tmp, file_id)
        enc = b""
        for name in sorted(os.listdir(d)):
            with open(os.path.join(d, name), "rb") as f:
                enc += f.read()
        if len(enc) != expected_size:
            raise RuntimeError("Reconstructed size does not match - file corrupted")
        return enc
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@app.template_filter("fmt")
def fmt_size(n):
    n = float(n or 0)
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


def is_admin():
    return session.get("admin") is True


# ---------- templates ----------
LAYOUT = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LabShare</title>
<style>
body{font-family:system-ui,Arial,sans-serif;margin:0;background:#f4f6fb;color:#1f2937}
header{background:#1e3a8a;color:#fff;padding:14px 24px;display:flex;justify-content:space-between;align-items:center}
header a{color:#fff;text-decoration:none;margin-left:16px}
main{max-width:980px;margin:24px auto;padding:0 16px}
.card{background:#fff;border-radius:10px;padding:20px;box-shadow:0 1px 4px #0001;margin-bottom:18px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 8px;border-bottom:1px solid #e5e7eb;font-size:14px}
input,select,button{padding:9px;border:1px solid #cbd5e1;border-radius:6px;font-size:14px}
button,.btn{background:#2563eb;color:#fff;border:0;cursor:pointer;text-decoration:none;padding:9px 14px;border-radius:6px;font-size:14px;display:inline-block}
.btn2{background:#475569}.row{display:flex;gap:8px;flex-wrap:wrap}.row input{flex:1;min-width:180px}
.msg{background:#dcfce7;padding:10px;border-radius:6px;margin-bottom:12px}
.err{background:#fee2e2}pre{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:6px;overflow:auto;font-size:13px}
</style></head><body>
<header><b>&#128218; LabShare - Notes &amp; Resource Cloud</b>
<nav><a href="{{ url_for('home') }}">Home</a>
{% if admin %}<a href="{{ url_for('upload') }}">Upload</a><a href="{{ url_for('logout') }}">Logout</a>
{% else %}<a href="{{ url_for('login') }}">Admin login</a>{% endif %}</nav></header>
<main>
{% with m = get_flashed_messages(with_categories=true) %}{% for c,t in m %}
<div class="msg {{ 'err' if c=='error' else '' }}">{{ t }}</div>{% endfor %}{% endwith %}
%%BODY%%
</main></body></html>"""


def page(body, **ctx):
    return render_template_string(LAYOUT.replace("%%BODY%%", body), admin=is_admin(), **ctx)


HOME = """
<div class="card"><form class="row" method="get">
<input name="q" placeholder="Search title, subject or file name" value="{{ q }}">
<select name="subject"><option value="">All subjects</option>
{% for s in subjects %}<option {% if s==subject %}selected{% endif %}>{{ s }}</option>{% endfor %}</select>
<button>Search</button></form></div>
<div class="card"><table>
<tr><th>Title</th><th>Subject</th><th>Size</th><th>Chunks</th><th>Downloads</th><th>Uploaded</th><th></th></tr>
{% for f in files %}<tr>
<td><a href="{{ url_for('details', fid=f.id) }}">{{ f.title }}</a><br><small>{{ f.filename }}</small></td>
<td>{{ f.subject }}</td><td>{{ f.size|fmt }}</td><td>{{ f.chunks }}</td><td>{{ f.downloads }}</td>
<td>{{ f.uploaded_at }}</td>
<td><a class="btn" href="{{ url_for('download', fid=f.id) }}">Download</a>
<a class="btn btn2" href="{{ url_for('download_enc', fid=f.id) }}">Encrypted</a></td></tr>
{% else %}<tr><td colspan="7">No resources found.</td></tr>{% endfor %}
</table></div>"""

LOGIN = """<div class="card"><h3>Admin login</h3>
<form method="post" class="row"><input type="password" name="password" placeholder="Admin password" required>
<button>Login</button></form></div>"""

UPLOAD = """<div class="card"><h3>Upload a resource</h3>
<form method="post" enctype="multipart/form-data">
<p><input name="title" placeholder="Title (e.g. Practical 3 - Sorting)" required style="width:100%"></p>
<p><input name="subject" list="subs" placeholder="Subject (e.g. Data Structures)" required style="width:100%">
<datalist id="subs">{% for s in subjects %}<option value="{{ s }}">{% endfor %}</datalist></p>
<p><input type="file" name="file" required></p>
<button>Encrypt, split and store in HDFS</button></form>
<p><small>Allowed: pdf, doc(x), ppt(x), xls(x), txt, zip, png, jpg, mp4. Max 50 MB.</small></p></div>"""

DETAILS = """<div class="card"><h3>{{ f.title }}</h3>
<p>Subject: <b>{{ f.subject }}</b> | Original file: <b>{{ f.filename }}</b> | Size: <b>{{ f.size|fmt }}</b>
| Encrypted size: <b>{{ f.enc_size|fmt }}</b> | Chunks: <b>{{ f.chunks }}</b> | Downloads: <b>{{ f.downloads }}</b></p>
<a class="btn" href="{{ url_for('download', fid=f.id) }}">Download (decrypted)</a>
<a class="btn btn2" href="{{ url_for('download_enc', fid=f.id) }}">Download encrypted (.enc)</a>
{% if admin %}<form method="post" action="{{ url_for('delete', fid=f.id) }}" style="display:inline"><button style="background:#dc2626">Delete</button></form>{% endif %}
</div>
<div class="card"><h4>Chunks stored in HDFS (<code>hdfs dfs -ls</code>)</h4><pre>{{ listing }}</pre></div>"""


# ---------- routes ----------
@app.route("/")
def home():
    q = request.args.get("q", "").strip()
    subject = request.args.get("subject", "").strip()
    sql, params = "SELECT * FROM files WHERE 1=1", []
    if q:
        sql += " AND (title LIKE ? OR subject LIKE ? OR filename LIKE ?)"
        params += [f"%{q}%"] * 3
    if subject:
        sql += " AND subject = ?"
        params.append(subject)
    sql += " ORDER BY uploaded_at DESC"
    with db() as con:
        files = con.execute(sql, params).fetchall()
        subjects = [r[0] for r in con.execute("SELECT DISTINCT subject FROM files ORDER BY subject")]
    return page(HOME, files=files, subjects=subjects, q=q, subject=subject)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["admin"] = True
            flash("Logged in as admin.")
            return redirect(url_for("upload"))
        flash("Wrong password.", "error")
    return page(LOGIN)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not is_admin():
        return redirect(url_for("login"))
    with db() as con:
        subjects = [r[0] for r in con.execute("SELECT DISTINCT subject FROM files ORDER BY subject")]
    if request.method == "POST":
        f = request.files.get("file")
        title = request.form["title"].strip()
        subject = request.form["subject"].strip()
        filename = secure_filename(f.filename or "")
        if not filename or filename.rsplit(".", 1)[-1].lower() not in ALLOWED:
            flash("File type not allowed.", "error")
            return redirect(url_for("upload"))
        data = f.read()
        enc = encrypt(data)
        fid = uuid.uuid4().hex[:12]
        try:
            chunks = store_in_hdfs(fid, enc)
        except Exception as e:
            flash(f"HDFS error: {e}", "error")
            return redirect(url_for("upload"))
        with db() as con:
            con.execute("INSERT INTO files VALUES (?,?,?,?,?,?,?,?,0)",
                        (fid, title, subject, filename, len(data), len(enc), chunks,
                         datetime.now().strftime("%Y-%m-%d %H:%M")))
        flash(f"Uploaded: encrypted and stored as {chunks} chunk(s) in HDFS.")
        return redirect(url_for("home"))
    return page(UPLOAD, subjects=subjects)


def get_row(fid):
    with db() as con:
        row = con.execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
    if not row:
        abort(404)
    return row


def count_download(fid):
    with db() as con:
        con.execute("UPDATE files SET downloads = downloads + 1 WHERE id=?", (fid,))


@app.route("/file/<fid>")
def details(fid):
    row = get_row(fid)
    try:
        listing = hdfs("-ls", f"{HDFS_ROOT}/{fid}")
    except Exception as e:
        listing = str(e)
    return page(DETAILS, f=row, listing=listing)


@app.route("/download/<fid>")
def download(fid):
    row = get_row(fid)
    try:
        data = decrypt(load_from_hdfs(fid, row["enc_size"]))
    except Exception as e:
        flash(f"Download failed: {e}", "error")
        return redirect(url_for("home"))
    count_download(fid)
    return send_file(io.BytesIO(data), as_attachment=True, download_name=row["filename"])


@app.route("/download-enc/<fid>")
def download_enc(fid):
    row = get_row(fid)
    try:
        enc = load_from_hdfs(fid, row["enc_size"])
    except Exception as e:
        flash(f"Download failed: {e}", "error")
        return redirect(url_for("home"))
    count_download(fid)
    return send_file(io.BytesIO(enc), as_attachment=True,
                     download_name=row["filename"] + ".enc")


@app.route("/delete/<fid>", methods=["POST"])
def delete(fid):
    if not is_admin():
        abort(403)
    get_row(fid)
    try:
        hdfs("-rm", "-r", "-skipTrash", f"{HDFS_ROOT}/{fid}")
    except Exception:
        pass
    with db() as con:
        con.execute("DELETE FROM files WHERE id=?", (fid,))
    flash("Deleted.")
    return redirect(url_for("home"))


init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
PYEOF

cat > run.sh <<'RUNEOF'
#!/bin/bash
cd "$(dirname "$0")"
export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))
export HADOOP_HOME=/opt/hadoop
export PATH=$PATH:$HADOOP_HOME/bin:$HADOOP_HOME/sbin
jps | grep -q NameNode || { start-dfs.sh; sleep 8; }
pkill -f "python app.py" 2>/dev/null
export LABSHARE_ADMIN_PASSWORD=${LABSHARE_ADMIN_PASSWORD:-admin123}
nohup ./venv/bin/python app.py > app.log 2>&1 &
sleep 2
echo "LabShare running on port 5000 (log: ~/labshare/app.log)"
RUNEOF
chmod +x run.sh

cat > docs-site/index.html <<'HTMLEOF'
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LabShare - Project Documentation</title>
<style>
:root{--bg:#f4f6fb;--fg:#1f2937;--card:#fff;--accent:#1e3a8a}
@media (prefers-color-scheme:dark){:root{--bg:#0f172a;--fg:#e2e8f0;--card:#1e293b;--accent:#60a5fa}}
body{margin:0;font-family:system-ui,Arial,sans-serif;background:var(--bg);color:var(--fg);line-height:1.6}
header{background:#1e3a8a;color:#fff;padding:40px 20px;text-align:center}
main{max-width:900px;margin:auto;padding:20px}
section{background:var(--card);border-radius:10px;padding:20px;margin:18px 0;box-shadow:0 1px 4px #0001}
h2{color:var(--accent);margin-top:0}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid #8884}
code,pre{background:#0f172a;color:#e2e8f0;border-radius:6px;padding:2px 6px}
pre{padding:12px;overflow:auto}
.flow{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.box{background:var(--accent);color:#fff;padding:8px 12px;border-radius:8px;font-size:14px}
footer{text-align:center;padding:20px;opacity:.7}
</style></head><body>
<header><h1>&#128218; LabShare</h1><p>Notes and Resource Cloud - encrypted, segmented storage on Hadoop HDFS</p></header>
<main>
<section><h2>Overview</h2>
<p>LabShare is a shared library for practical manuals, lecture notes, presentations and lab reports.
A lab administrator uploads a resource; students search by subject and download it through the Cloud Controller.
Files are encrypted with AES-256-GCM, split into 1 MB segments and stored in Hadoop HDFS running on an AWS EC2 server.
This documentation website is hosted on Amazon S3 and delivered over HTTPS by Amazon CloudFront (CDN).</p></section>

<section><h2>Architecture</h2>
<div class="flow"><span class="box">User</span>&rarr;<span class="box">Flask Cloud Controller</span>&rarr;
<span class="box">AES-256 encryption</span>&rarr;<span class="box">1 MB segmentation</span>&rarr;<span class="box">Hadoop HDFS (EC2)</span></div>
<p>Download reverses the flow: chunks are read from HDFS in order, joined, verified by size and decrypted (or given as the encrypted .enc file).</p>
<div class="flow"><span class="box">Docs files</span>&rarr;<span class="box">Amazon S3 (private)</span>&rarr;<span class="box">CloudFront CDN</span>&rarr;<span class="box">Visitor (HTTPS)</span></div></section>

<section><h2>Features</h2><table>
<tr><th>Feature</th><th>Implementation</th></tr>
<tr><td>Upload / download</td><td>Flask routes, admin login for uploads</td></tr>
<tr><td>Subject categories &amp; search</td><td>SQLite + LIKE queries</td></tr>
<tr><td>Encrypted storage</td><td>AES-256-GCM (Python cryptography library)</td></tr>
<tr><td>File segmentation</td><td>Application-level 1 MB chunks (chunk_0000, chunk_0001, ...)</td></tr>
<tr><td>Distributed storage</td><td>Hadoop HDFS (NameNode + DataNode) on AWS EC2</td></tr>
<tr><td>Encrypted download</td><td>Separate "Encrypted (.enc)" download button</td></tr>
<tr><td>File info &amp; counters</td><td>Size, chunks, subject, upload time, download count</td></tr>
<tr><td>Static site + CDN</td><td>Amazon S3 + CloudFront with HTTPS</td></tr></table>
<p><small>Note: the 1 MB chunks are created by our application; HDFS also manages its own internal blocks automatically.</small></p></section>

<section><h2>Screenshots</h2>
<p>Add your screenshots here (home page, upload page, chunk listing, HDFS <code>-ls</code> output, CloudFront URL).</p></section>

<section><h2>How to run</h2>
<pre>ssh -i labshare.pem ubuntu@SERVER_IP
bash setup_labshare.sh
~/labshare/run.sh
# open http://SERVER_IP:5000</pre></section>

<section><h2>Test cases</h2><table>
<tr><th>#</th><th>Test</th><th>Expected</th></tr>
<tr><td>1</td><td>Upload a PDF as admin</td><td>Stored as N chunks in HDFS</td></tr>
<tr><td>2</td><td>Open file details</td><td>HDFS listing shows chunk files</td></tr>
<tr><td>3</td><td>Download (decrypted)</td><td>PDF opens normally</td></tr>
<tr><td>4</td><td>Download encrypted (.enc)</td><td>File is unreadable without the key</td></tr>
<tr><td>5</td><td>Search by subject</td><td>Only matching files listed</td></tr>
<tr><td>6</td><td>Download twice</td><td>Download count increases by 2</td></tr></table></section>
</main>
<footer>LabShare - College mini project</footer>
</body></html>
HTMLEOF

echo "== 5/5 Starting LabShare =="
./run.sh

echo ""
echo "DONE. Open in your browser:  http://<YOUR_EC2_PUBLIC_IP>:5000"
echo "Admin password: admin123   (change: LABSHARE_ADMIN_PASSWORD=yourpass ./run.sh)"
