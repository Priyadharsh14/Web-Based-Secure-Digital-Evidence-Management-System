from flask import Flask, render_template, request, redirect, session, send_file
import sqlite3, os, bcrypt
from utils.crypto import encrypt_file, decrypt_file, generate_hash

app = Flask(__name__)
app.secret_key = "secret123"

UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------------- DATABASE ----------------

def get_db():
    return sqlite3.connect("database.db")

def init_db():
    db = get_db()
    cur = db.cursor()

    # USERS
    cur.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        role TEXT
    )""")

    # CASES
    cur.execute("""CREATE TABLE IF NOT EXISTS cases(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT
    )""")

    # EVIDENCE
    cur.execute("""CREATE TABLE IF NOT EXISTS evidence(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        case_id INTEGER,
        hash TEXT,
        nonce BLOB,
        tag BLOB,
        key BLOB
    )""")

    # LOGS (CHAIN OF CUSTODY)
    cur.execute("""CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file TEXT,
        case_id INTEGER,
        user TEXT,
        action TEXT,
        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

    db.commit()
    db.close()

init_db()

# ---------------- HOME ----------------

@app.route("/")
def home():
    return render_template("index.html")

# ---------------- AUTH ----------------

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = bcrypt.hashpw(request.form["password"].encode(), bcrypt.gensalt())
        role = request.form["role"]

        db = get_db()
        db.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)",
                   (username,password,role))
        db.commit()
        return redirect("/login")

    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if user and bcrypt.checkpw(password.encode(), user[2]):
            session["user"] = user[1]
            session["role"] = user[3]

            if user[3] == "Investigator":
                return redirect("/investigator")
            else:
                return redirect("/authority")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------- INVESTIGATOR ----------------

@app.route("/investigator")
def investigator():
    if "role" not in session or session["role"] != "Investigator":
        return redirect("/login")

    db = get_db()

    cases = db.execute("SELECT * FROM cases").fetchall()
    evidence = db.execute("SELECT * FROM evidence").fetchall()

    evidence_map = {}
    for c in cases:
        count = db.execute(
            "SELECT COUNT(*) FROM evidence WHERE case_id=?", 
            (c[0],)
        ).fetchone()[0]
        evidence_map[c[0]] = count

    return render_template(
        "investigator_dashboard.html",
        cases=cases,
        evidence_map=evidence_map,
        evidence_list=evidence
    )

@app.route("/create_case", methods=["POST"])
def create_case():
    title = request.form["title"]
    desc = request.form["description"]

    db = get_db()
    db.execute("INSERT INTO cases(title,description) VALUES(?,?)", (title, desc))
    db.commit()

    return redirect("/investigator")

@app.route("/upload/<int:case_id>", methods=["POST"])
def upload(case_id):
    if "role" not in session or session["role"] != "Investigator":
        return redirect("/login")

    file = request.files["file"]
    data = file.read()

    ciphertext, nonce, tag, key = encrypt_file(data)
    file_hash = generate_hash(data)

    path = os.path.join(UPLOAD_FOLDER, file.filename)
    with open(path, "wb") as f:
        f.write(ciphertext)

    db = get_db()

    db.execute("""INSERT INTO evidence(filename,case_id,hash,nonce,tag,key)
                  VALUES(?,?,?,?,?,?)""",
               (file.filename, case_id, file_hash, nonce, tag, key))

    db.execute("""INSERT INTO logs(file,case_id,user,action)
                  VALUES(?,?,?,?)""",
               (file.filename, case_id, session["user"], "UPLOAD"))

    db.commit()

    return redirect("/investigator")

# ---------------- AUTHORITY + SEARCH ----------------

@app.route("/authority", methods=["GET", "POST"])
def authority():
    if "role" not in session or session["role"] != "Authority":
        return redirect("/login")

    db = get_db()
    search_query = ""

    if request.method == "POST":
        search_query = request.form.get("search", "")

        cases = db.execute(
            "SELECT * FROM cases WHERE title LIKE ?",
            ('%' + search_query + '%',)
        ).fetchall()
    else:
        cases = db.execute("SELECT * FROM cases").fetchall()

    return render_template(
        "authority_dashboard.html",
        cases=cases,
        search_query=search_query
    )

# ---------------- CASE DETAILS + TIMELINE ----------------

@app.route("/case/<int:id>")
def case_details(id):
    if "role" not in session or session["role"] != "Authority":
        return redirect("/login")

    db = get_db()

    evidence = db.execute(
        "SELECT * FROM evidence WHERE case_id=?", (id,)
    ).fetchall()

    logs = db.execute(
        "SELECT * FROM logs WHERE case_id=? ORDER BY time DESC", (id,)
    ).fetchall()

    return render_template(
        "case_details.html",
        evidence=evidence,
        logs=logs,
        case_id=id
    )

# ---------------- DOWNLOAD ----------------

@app.route("/download/<int:id>")
def download(id):
    if "role" not in session or session["role"] != "Authority":
        return redirect("/login")

    db = get_db()
    e = db.execute("SELECT * FROM evidence WHERE id=?", (id,)).fetchone()

    path = os.path.join(UPLOAD_FOLDER, e[1])
    with open(path, "rb") as f:
        ciphertext = f.read()

    data = decrypt_file(ciphertext, e[4], e[5], e[6])

    temp_file = "temp_" + e[1]
    with open(temp_file, "wb") as f:
        f.write(data)

    db.execute("""INSERT INTO logs(file,case_id,user,action)
                  VALUES(?,?,?,?)""",
               (e[1], e[2], session["user"], "DOWNLOAD"))
    db.commit()

    return send_file(temp_file, as_attachment=True)

# ---------------- AUDIT LOGS ----------------

@app.route("/logs")
def logs():
    if "role" not in session:
        return redirect("/login")

    db = get_db()
    logs = db.execute("SELECT * FROM logs ORDER BY time DESC").fetchall()

    return render_template("logs.html", logs=logs)

# ---------------- RUN ----------------

if __name__ == "__main__":
    app.run(debug=True)