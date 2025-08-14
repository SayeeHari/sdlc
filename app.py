from flask import Flask, render_template, request, redirect, url_for, flash, send_file, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
import pymysql
import jwt
from functools import wraps
import string
import json
import datetime
import os
from werkzeug.utils import secure_filename
from pathlib import Path
from fpdf import FPDF
import glob
from PIL import Image

# ------------------ Flask App Config ------------------
app = Flask(__name__)
app.secret_key = 'Sayee1234'
SECRET_KEY = "URWAH28"

# ------------------ Allowed File Types ------------------
ALLOWED_FILE_EXTENSIONS = {"png", "jpg", "jpeg", "gif","pdf","xls","xlsx"}

def allowed_file(filename):
    return (
        bool(filename) 
        and '.' in filename 
        and filename.rsplit('.', 1)[1].lower() in ALLOWED_FILE_EXTENSIONS
    )


# Find project base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Set uploads folder path inside project
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

# Create folder if it doesn't exist
if not os.path.isdir(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Store in Flask config
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# ------------------ Controls List ------------------
CONTROLS = [
    "Control 1: Access Management",
    "Control 2: Data Encryption",
    "Control 3: Network Security",
    "Control 4: Incident Response",
    "Control 5: Physical Security",
    "Control 6: Vendor Management",
    "Control 7: Security Training",
    "Control 8: Vulnerability Management",
    "Control 9: Backup and Recovery",
    "Control 10: Audit Logging"
]

# MySQL Config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'audit_hari'        # Change if your MySQL username is different
app.config['MYSQL_PASSWORD'] = 'smile2003'  # Replace with your MySQL Workbench password
app.config['MYSQL_DB'] = 'sdlc'

mysql = MySQL(app)

connection = pymysql.connect(
    host="localhost",
    user="audit_hari",
    password="smile2003",
    database="sdlc"
)
cursor = connection.cursor()


def token_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.cookies.get("token")
            if not token:
                flash("You must be logged in to access this page", "error")
                return redirect(url_for("login"))
            try:
                data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            except jwt.ExpiredSignatureError:
                flash("Your session has expired. Please log in again.", "error")
                return redirect(url_for("login"))
            except jwt.InvalidTokenError:
                flash("Invalid token. Please log in again.", "error")
                return redirect(url_for("login"))

            # If a role is required, check it
            if role and data.get("role") != role:
                flash("You are not authorized to access this page", "error")
                return redirect(url_for("login"))

            # Pass decoded token data to the route
            return f(data, *args, **kwargs)
        return wrapper
    return decorator

@app.route("/")
def home( ):
    return render_template("index.html")

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        auditee_name = request.form["auditee_name"]
        organization_name = request.form["organization_name"]
        date_of_audit = request.form["date_of_audit"]
        mobile_number = request.form["mobile_number"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])
        org_type = request.form["org_type"]

        
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO auditees 
            (auditee_name, organization_name, date_of_audit, mobile_number, email, password_hash, org_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (auditee_name, organization_name, date_of_audit, mobile_number, email, password, org_type))
        mysql.connection.commit()
        cur.close()

    
        return redirect(url_for("success"))
      
    return render_template("register.html")


@app.route("/success")
def success():
    return render_template("success.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role = request.form.get('role', '').lower()
        email = request.form['email']
        password = request.form['password']

        # Helper function to generate token
        def generate_token(user_id, role, email):
            payload = {
                "user_id": user_id,
                "role": role,
                "email": email,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # token expires in 1 hour
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
            return token

        if role == 'tester':
          if email == "tester@gmail.com" and password == "tester123":
            token = generate_token(user_id=0, role="tester", email=email)
            resp = redirect(url_for("tester_dashboard"))
            resp.set_cookie("token", token, httponly=True, samesite='Strict')
            return resp

          else:
                flash("Invalid credentials for Tester.", "danger")
                return redirect(url_for('login'))

        elif role == 'auditor':
            if email == "auditor@gmail.com" and password == "auditor123":
                token = generate_token(user_id=0, role="auditor", email=email)
                resp = redirect(url_for("auditor_dashboard"))
                resp.set_cookie("token", token, httponly=True, samesite='Strict')
                return resp
            else:
                flash("Invalid credentials for Auditor.", "danger")
                return redirect(url_for('login'))

        elif role == 'auditee':
            cur = mysql.connection.cursor()
            cur.execute("SELECT id, password_hash FROM auditees WHERE email=%s", (email,))
            auditee = cur.fetchone()
            cur.close()

            if auditee and check_password_hash(auditee[1], password):
                token = generate_token(user_id=auditee[0], role="auditee", email=email)
                resp = redirect(url_for("auditee_dashboard"))
                resp.set_cookie("token", token, httponly=True, samesite='Strict')
                return resp
            else:
                flash("Invalid credentials for Auditee.", "danger")
                return redirect(url_for('login'))

        else:
            flash("Please select a valid role.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/auditee_dashboard')
@token_required(role="auditee")
def auditee_dashboard(decoded_token):
    return render_template('auditee_dashboard.html', user=decoded_token)

@app.route("/data_submission", methods=["GET", "POST"])
@token_required(role="auditee")
def data_submission(decoded_token):
    if request.method == "POST":
        # Step 1: Check if verifying ID
        if "final_submit" not in request.form:
            entered_id = request.form["next_step_id"].strip()
            # Replace with real validation logic
            if entered_id == "Ameya@123":  
                return render_template("data_submission.html", valid_id=True, next_step_id=entered_id)
            else:
                flash("Invalid Next Step ID.", "danger")
                return render_template("data_submission.html", valid_id=False)

        # Step 2: Handle file upload and auditee data
        asset_file = request.files["asset_list"]
        checklist_file = request.files["checklist"]
        auditee_count = int(request.form["auditee_count"])
        auditee_names_str = request.form.get("auditee_names", "")
        auditee_names =  [name.strip() for name in auditee_names_str.split(",") if name.strip()]

        if not (asset_file and allowed_file(asset_file.filename)):
            flash("Invalid Asset List file.", "danger")
            return render_template("data_submission.html", valid_id=True, next_step_id=request.form["next_step_id"])
        filename = secure_filename(asset_file.filename)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        asset_file.save(save_path)
        if not (checklist_file and allowed_file(checklist_file.filename)):
            flash("Invalid Checklist file.", "danger")
            return render_template("data_submission.html", valid_id=True, next_step_id=request.form["next_step_id"])

        asset_filename = secure_filename(asset_file.filename)
        checklist_filename = secure_filename(checklist_file.filename)

        asset_path = os.path.join(app.config["UPLOAD_FOLDER"], asset_filename)
        checklist_path = os.path.join(app.config["UPLOAD_FOLDER"], checklist_filename)

        asset_file.save(asset_path)
        checklist_file.save(checklist_path)

        auditee_names_str = ",".join(auditee_names)
        
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO data_submissions 
            (auditee_id, next_step_id, asset_list_filename, checklist_filename, auditee_count, auditee_names)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            decoded_token["user_id"],
            request.form["next_step_id"],
            asset_filename,
            checklist_filename,
            auditee_count,
            auditee_names_str 
        ))
        mysql.connection.commit()
        cur.close()

        # Save auditee data to DB if needed
        print("Auditees involved:", auditee_names)

        flash("Data submitted successfully!", "success")
        return redirect(url_for("auditee_dashboard"))

    return render_template("data_submission.html", valid_id=False)

@app.route("/control_evidence", methods=["GET", "POST"])
@token_required(role="auditee")
def control_evidence(decoded_token):
    cur = mysql.connection.cursor()

    if request.method == "POST":
        # Step 1: Validate Next Step ID
        if "control_1" not in request.form:
            entered_id = request.form["next_step_id"].strip()
            if entered_id == "CRS@123":  # Replace with real validation
                return render_template("control_evidence_form.html", 
                                       controls=CONTROLS, 
                                       next_step_id=entered_id)
            else:
                flash("Invalid Next Step ID.", "danger")
                return render_template("control_evidence.html")

        # Step 2: Save control evidence
        compliant_count = 0
        non_compliant_count = 0

        for i in range(1, 11):
            status = request.form.get(f"control_{i}", "").strip()  # default empty string
            if status not in ("compliant", "non-compliant"):
                status = "non-compliant"  # or some default

            poc_file = request.files.get(f"poc_{i}")
            filename = None

            if poc_file and Path(poc_file.filename).suffix.lower() in ALLOWED_FILE_EXTENSIONS:
                filename = secure_filename(poc_file.filename)
                save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                poc_file.save(save_path)
                print(f"✅ Saved POC file at {save_path}")

            # Count compliant/non-compliant for summary
            if status == "compliant":
                compliant_count += 1
            elif status == "non-compliant":
                non_compliant_count += 1

            # Insert each control submission individually
            cur.execute("""
                INSERT INTO control_evidence_details
                (auditee_id, control_id, status, evidence_file)
                VALUES (%s, %s, %s, %s)
            """, (decoded_token["user_id"], i, status, filename))

        mysql.connection.commit()
        cur.close()

        flash("Control evidence submitted successfully!", "success")
        return render_template("control_evidence_summary.html", 
                               total=10, 
                               compliant=compliant_count, 
                               non_compliant=non_compliant_count)

    return render_template("control_evidence.html")



@app.route("/auditor_dashboard")
@token_required(role="auditor")
def auditor_dashboard(decoded_token):
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT auditee_name, organization_name, date_of_audit,mobile_number,email,org_type
        FROM auditees
        WHERE id = %s
    """, (decoded_token['user_id'],))
    auditor = cur.fetchone()

    # 1. Total registered auditees
    cur.execute("SELECT COUNT(*) FROM auditees")
    total_auditees = cur.fetchone()[0]

    # 2. Number of auditees who submitted data
    cur.execute("SELECT COUNT(DISTINCT id) FROM data_submissions")
    submitted_data = cur.fetchone()[0]

    # 3. Number of auditees who submitted control evidence
    cur.execute("SELECT COUNT(DISTINCT id) FROM control_evidence_submissions")
    submitted_evidence = cur.fetchone()[0]

    # 4. Summary count of compliant and non-compliant
    cur.execute("""
        SELECT SUM(compliant_controls), SUM(non_compliant_controls)
        FROM control_evidence_submissions
    """)
    summary = cur.fetchone()
    compliant_count = summary[0] or 0
    non_compliant_count = summary[1] or 0

    cur.close()

    return render_template(
        "auditor_dashboard.html",
        auditor=auditor,
        total_auditees=total_auditees,
        submitted_data=submitted_data,
        submitted_evidence=submitted_evidence,
        compliant_count=compliant_count,
        non_compliant_count=non_compliant_count
    )

# PDF Download

@app.route("/download_all_evidence")
@token_required(role="auditor")
def download_all_evidence(decoded_token):
    cur = mysql.connection.cursor()

    # Fetch all auditees who have submitted control evidence
    cur.execute("""
        SELECT DISTINCT a.id, a.auditee_name, a.organization_name, a.date_of_audit, a.mobile_number, a.email
        FROM auditees a
        JOIN control_evidence_details e ON a.id = e.auditee_id
    """)
    all_auditees = cur.fetchall()

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Consolidated Evidence Report", ln=True, align="C")
    pdf.ln(5)

    pdf.set_font("Arial", "", 12)

    for auditee in all_auditees:
        auditee_id, name, org, audit_date, mobile, email = auditee

        # Auditee info
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, f"Auditee Name: {name}", ln=True)
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 8, f"Organization: {org}", ln=True)
        pdf.cell(0, 8, f"Audit Date: {audit_date}", ln=True)
        pdf.cell(0, 8, f"Mobile Number: {mobile}", ln=True)
        pdf.cell(0, 8, f"Email: {email}", ln=True)
        pdf.ln(3)

        # Fetch evidence for this auditee
        cur.execute("""
            SELECT c.control_name, e.status, e.evidence_file
            FROM control_evidence_details e
            JOIN controls c ON e.control_id = c.id
            WHERE e.auditee_id = %s
            ORDER BY e.control_id
        """, (auditee_id,))
        evidence_data = cur.fetchall()

        for control_name, status, file_path in evidence_data:
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 8, control_name, ln=True)

            pdf.set_font("Arial", "", 10)
            pdf.cell(0, 8, f"Status: {status}", ln=True)

            if file_path:
                file_path_full = os.path.join(app.config["UPLOAD_FOLDER"], file_path)

                if os.path.exists(file_path_full):
                    try:
                        # Auto-scale image to fit page width
                        max_width = 150  # mm
                        pdf.image(file_path_full, w=max_width)
                    except Exception as e:
                        pdf.cell(0, 8, f"Error loading image: {str(e)}", ln=True)
                else:
                    pdf.cell(0, 8, f"Evidence File: {os.path.basename(file_path)} (missing)", ln=True)

            pdf.ln(2)

        pdf.ln(5)  # space between auditees

    cur.close()

    pdf_path = os.path.join(app.config["UPLOAD_FOLDER"], "consolidated_evidence.pdf")
    pdf.output(pdf_path)

    return send_file(pdf_path, as_attachment=True)


@app.route("/tester_dashboard")
@token_required(role="tester")
def tester_dashboard(decoded_token):
    cur = mysql.connection.cursor()

    # Total auditees
    cur.execute("SELECT COUNT(*) FROM auditees")
    total_auditees = cur.fetchone()[0]

    # Number of auditees who submitted data
    cur.execute("SELECT COUNT(DISTINCT auditee_id) FROM data_submissions")
    submitted_data = cur.fetchone()[0]

    # Number of auditees who submitted control evidence
    cur.execute("SELECT COUNT(DISTINCT auditee_id) FROM control_evidence_details")
    submitted_evidence = cur.fetchone()[0]

    cur.close()
    return render_template(
        "tester_dashboard.html",
        total_auditees=total_auditees,
        submitted_data=submitted_data,
        submitted_evidence=submitted_evidence
    )

@app.route("/tester/view_evidence")
@token_required(role="tester")
def tester_view_evidence(decoded_token):
    cur = mysql.connection.cursor()

    # Fetch only compliant evidence
    cur.execute("""
        SELECT a.id, a.auditee_name, c.control_name, e.status, e.evidence_file
        FROM control_evidence_details e
        JOIN auditees a ON e.auditee_id = a.id
        JOIN controls c ON e.control_id = c.id
        WHERE LOWER(e.status) = 'compliant'
    """)
    evidence_data = cur.fetchall()
    cur.close()

    # Pass data to template
    return render_template("tester_view_evidence.html", evidence=evidence_data)


@app.route("/tester/download/<filename>")
@token_required(role="tester")
def tester_download_file(decoded_token, filename):
    try:
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)
    except FileNotFoundError:
        flash("File not found!", "danger")
        return redirect(url_for("tester_view_evidence"))


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    filename = os.path.basename(filename)  # Security
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)



if __name__ == "__main__":
    app.run(debug=True)


