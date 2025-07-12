# pharmacy_stock_system/app.py
# This is the complete and final version of the application file.
# It includes all features: Auth, Charts, Pagination, Search, CRUD, Dispensing, User Management, and Audit Trail.

import sqlite3
import datetime
import io
import csv
import json
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_for_sessions'

# --- Configuration ---
EXPIRY_ALERT_DAYS = 30 
LOW_STOCK_THRESHOLD = 50 # UPDATED: Changed from 10 to 50
ITEMS_PER_PAGE = 10

# --- Database Helper Functions ---
def get_db_connection():
    """Creates a database connection."""
    conn = sqlite3.connect('pharmacy.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_medication(med_id):
    """Fetches a single medication by its ID."""
    conn = get_db_connection()
    medication = conn.execute('SELECT * FROM medications WHERE id = ?', (med_id,)).fetchone()
    conn.close()
    return medication

# --- NEW: Audit Log Helper ---
def log_audit(action, user_id=None, username=None):
    """Logs an action to the audit_log table."""
    if user_id is None and 'user_id' in session:
        user_id = session['user_id']
    if username is None and 'username' in session:
        username = session['username']
    
    conn = get_db_connection()
    conn.execute('INSERT INTO audit_log (user_id, username, action) VALUES (?, ?, ?)',
                 (user_id, username, action))
    conn.commit()
    conn.close()

# --- Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_role' not in session or session['user_role'] != 'admin':
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Authentication Routes ---
@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['user_role'] = user['role']
            log_audit(f"User '{username}' logged in successfully.")
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            log_audit(f"Failed login attempt for username '{username}'.", username=username)
            flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    log_audit(f"User '{session.get('username')}' logged out.")
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Core Application Routes ---
@app.route('/')
@login_required
def index():
    search_query = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    offset = (page - 1) * ITEMS_PER_PAGE

    conn = get_db_connection()
    
    base_query = "FROM medications "
    count_query = "SELECT COUNT(*) "
    data_query = "SELECT * "
    params = []

    if search_query:
        search_term = f"%{search_query}%"
        where_clause = "WHERE name LIKE ? OR category LIKE ? OR batch_number LIKE ? "
        base_query += where_clause
        params.extend([search_term, search_term, search_term])
    
    total_items = conn.execute(count_query + base_query, params).fetchone()[0]
    total_pages = (total_items + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE if total_items > 0 else 1

    paginated_query = data_query + base_query + "ORDER BY name ASC LIMIT ? OFFSET ?"
    meds = conn.execute(paginated_query, params + [ITEMS_PER_PAGE, offset]).fetchall()

    top_meds_data = conn.execute("SELECT name, quantity FROM medications ORDER BY quantity DESC LIMIT 5").fetchall()
    top_meds_chart = {"labels": [row['name'] for row in top_meds_data], "data": [row['quantity'] for row in top_meds_data]}

    category_data = conn.execute("SELECT category, COUNT(*) as count FROM medications WHERE category IS NOT NULL AND category != '' GROUP BY category").fetchall()
    category_chart = {"labels": [row['category'] for row in category_data], "data": [row['count'] for row in category_data]}

    all_meds_for_alerts = conn.execute('SELECT * FROM medications').fetchall()
    conn.close()
    
    low_stock_alerts = []
    expiry_alerts = []
    today = datetime.date.today()
    expiry_limit_date = today + datetime.timedelta(days=EXPIRY_ALERT_DAYS)
    for med in all_meds_for_alerts:
        if med['quantity'] <= LOW_STOCK_THRESHOLD:
            low_stock_alerts.append(med)
        try:
            expiry_date = datetime.datetime.strptime(med['expiry_date'], '%Y-%m-%d').date()
            if today <= expiry_date < expiry_limit_date:
                expiry_alerts.append(med)
        except (ValueError, TypeError):
            continue
            
    return render_template('index.html', 
                           medications=meds, 
                           low_stock_alerts=low_stock_alerts,
                           expiry_alerts=expiry_alerts,
                           low_stock_threshold=LOW_STOCK_THRESHOLD,
                           expiry_alert_days=EXPIRY_ALERT_DAYS,
                           search_query=search_query,
                           current_page=page,
                           total_pages=total_pages,
                           top_meds_chart=json.dumps(top_meds_chart),
                           category_chart=json.dumps(category_chart))

@app.route('/dispense', methods=('GET', 'POST'))
@login_required
def dispense():
    if request.method == 'POST':
        med_ids = request.form.getlist('med_id')
        quantities = request.form.getlist('quantity')
        prescription_note = request.form.get('prescription_note', 'Dispensed via prescription')
        if not med_ids:
            flash('No medications were added to the prescription.', 'error')
            return redirect(url_for('dispense'))
        conn = get_db_connection()
        can_process = True
        meds_to_dispense_names = []
        for i, med_id in enumerate(med_ids):
            med = conn.execute('SELECT * FROM medications WHERE id = ?', (med_id,)).fetchone()
            meds_to_dispense_names.append(med['name'])
            try:
                quantity_to_dispense = int(quantities[i])
                if quantity_to_dispense <= 0:
                    flash(f"Quantity for {med['name']} must be positive.", 'error')
                    can_process = False
                if med['quantity'] < quantity_to_dispense:
                    flash(f"Not enough stock for {med['name']}. Available: {med['quantity']}, Required: {quantity_to_dispense}", 'error')
                    can_process = False
            except (ValueError, IndexError):
                flash('Invalid quantity provided for one or more medications.', 'error')
                can_process = False
                break
        if can_process:
            try:
                for i, med_id in enumerate(med_ids):
                    quantity_to_dispense = int(quantities[i])
                    conn.execute('UPDATE medications SET quantity = quantity - ? WHERE id = ?', (quantity_to_dispense, med_id))
                    conn.execute('INSERT INTO stock_movements (medication_id, type, quantity, note) VALUES (?, ?, ?, ?)',
                                 (med_id, 'out', quantity_to_dispense, prescription_note))
                conn.commit()
                log_audit(f"Dispensed prescription: {', '.join(meds_to_dispense_names)}. Note: {prescription_note}")
                flash('Prescription processed successfully! Stock has been updated.', 'success')
                return redirect(url_for('index'))
            except sqlite3.Error as e:
                conn.rollback()
                flash(f'A database error occurred: {e}', 'error')
            finally:
                conn.close()
        else:
            conn.close()
            return redirect(url_for('dispense'))
    conn = get_db_connection()
    medications = conn.execute('SELECT id, name, quantity FROM medications WHERE quantity > 0 ORDER BY name ASC').fetchall()
    conn.close()
    return render_template('dispense.html', medications=medications)

# --- Admin-Only Routes ---
@app.route('/add', methods=('GET', 'POST'))
@login_required
@admin_required
def add():
    if request.method == 'POST':
        form_data = request.form
        name = form_data.get('name')
        category = form_data.get('category')
        manufacturer = form_data.get('manufacturer')
        batch_number = form_data.get('batch_number')
        expiry_date = form_data.get('expiry_date')
        quantity_str = form_data.get('quantity')
        price_str = form_data.get('price')
        errors = []
        if not name: errors.append("Name is required.")
        if not expiry_date: errors.append("Expiry Date is required.")
        if not quantity_str: errors.append("Quantity is required.")
        quantity = 0
        if quantity_str:
            try:
                quantity = int(quantity_str)
                if quantity < 0: errors.append("Quantity cannot be negative.")
            except ValueError:
                errors.append("Quantity must be a whole number.")
        price = 0.0
        if price_str:
            try:
                price = float(price_str)
                if price < 0.0: errors.append("Price cannot be negative.")
            except ValueError:
                errors.append("Price must be a valid number (e.g., 10.50).")
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('add_medication.html', form_data=form_data)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO medications (name, category, manufacturer, batch_number, expiry_date, quantity, price)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (name, category, manufacturer, batch_number, expiry_date, quantity, price))
        med_id = cursor.lastrowid
        conn.execute('INSERT INTO stock_movements (medication_id, type, quantity, note) VALUES (?, ?, ?, ?)',
                     (med_id, 'in', quantity, 'Initial stock'))
        conn.commit()
        conn.close()
        log_audit(f"Added new medication: '{name}' (Quantity: {quantity}).")
        flash(f'Medication "{name}" added successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('add_medication.html', form_data={})

@app.route('/edit/<int:med_id>', methods=('GET', 'POST'))
@login_required
@admin_required
def edit(med_id):
    medication = get_medication(med_id)
    if medication is None:
        flash('Medication not found!', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        form_data = request.form
        name = form_data.get('name')
        category = form_data.get('category')
        manufacturer = form_data.get('manufacturer')
        batch_number = form_data.get('batch_number')
        expiry_date = form_data.get('expiry_date')
        price_str = form_data.get('price')
        errors = []
        if not name: errors.append("Name is required.")
        if not expiry_date: errors.append("Expiry Date is required.")
        price = 0.0
        if price_str:
            try:
                price = float(price_str)
                if price < 0.0: errors.append("Price cannot be negative.")
            except ValueError:
                errors.append("Price must be a valid number.")
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('edit_medication.html', medication=form_data, med_id=med_id)
        conn = get_db_connection()
        conn.execute('''
            UPDATE medications SET name = ?, category = ?, manufacturer = ?, batch_number = ?, 
            expiry_date = ?, price = ? WHERE id = ?
        ''', (name, category, manufacturer, batch_number, expiry_date, price, med_id))
        conn.commit()
        conn.close()
        log_audit(f"Edited medication details for '{name}' (ID: {med_id}).")
        flash(f'Medication details updated successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('edit_medication.html', medication=medication, med_id=med_id)

@app.route('/delete/<int:med_id>', methods=('POST',))
@login_required
@admin_required
def delete(med_id):
    medication = get_medication(med_id)
    if medication:
        med_name = medication['name']
        conn = get_db_connection()
        conn.execute('DELETE FROM stock_movements WHERE medication_id = ?', (med_id,))
        conn.execute('DELETE FROM medications WHERE id = ?', (med_id,))
        conn.commit()
        conn.close()
        log_audit(f"Deleted medication: '{med_name}' (ID: {med_id}).")
        flash(f'Medication "{med_name}" and all its history deleted!', 'success')
    else:
        flash('Medication not found!', 'error')
    return redirect(url_for('index'))

@app.route('/stock/<int:med_id>', methods=('GET', 'POST'))
@login_required
@admin_required
def stock(med_id):
    medication = get_medication(med_id)
    if medication is None:
        flash('Medication not found!', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        movement_type = request.form.get('type')
        quantity_str = request.form.get('quantity')
        note = request.form.get('note')
        try:
            quantity_change = int(quantity_str)
            if quantity_change <= 0: raise ValueError("Quantity must be positive")
        except (ValueError, TypeError, AttributeError):
            flash('Please enter a valid positive number for quantity.', 'error')
            return redirect(url_for('stock', med_id=med_id))
        current_quantity = medication['quantity']
        if movement_type == 'out' and quantity_change > current_quantity:
            flash(f'Cannot remove {quantity_change} units. Only {current_quantity} are in stock.', 'error')
            return redirect(url_for('stock', med_id=med_id))
        else:
            new_quantity = current_quantity + quantity_change if movement_type == 'in' else current_quantity - quantity_change
            conn = get_db_connection()
            conn.execute('UPDATE medications SET quantity = ? WHERE id = ?', (new_quantity, med_id))
            conn.execute('INSERT INTO stock_movements (medication_id, type, quantity, note) VALUES (?, ?, ?, ?)',
                         (med_id, movement_type, quantity_change, note))
            conn.commit()
            conn.close()
            log_audit(f"Adjusted stock for '{medication['name']}'. Type: {movement_type.upper()}, Quantity: {quantity_change}, Note: {note}")
            flash('Stock updated successfully!', 'success')
            return redirect(url_for('index'))
    conn = get_db_connection()
    history = conn.execute('SELECT * FROM stock_movements WHERE medication_id = ? ORDER BY date DESC', (med_id,)).fetchall()
    conn.close()
    return render_template('stock_movement.html', medication=medication, history=history)

@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html')

@app.route('/report/full_stock_csv')
@login_required
def full_stock_csv():
    conn = get_db_connection()
    meds = conn.execute('SELECT * FROM medications ORDER BY name ASC').fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    header = ['ID', 'Name', 'Category', 'Manufacturer', 'Batch Number', 'Expiry Date', 'Quantity', 'Price']
    writer.writerow([h.replace('_', ' ').title() for h in header])
    for med in meds:
        writer.writerow([med[key] for key in med.keys()])
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=full_stock_report.csv'
    response.headers['Content-type'] = 'text/csv'
    log_audit("Generated a full stock CSV report.")
    return response

# --- User Management Routes ---
@app.route('/users')
@login_required
@admin_required
def users():
    conn = get_db_connection()
    user_list = conn.execute('SELECT id, username, role FROM users ORDER BY username').fetchall()
    conn.close()
    return render_template('users.html', users=user_list)

@app.route('/users/add', methods=('POST',))
@login_required
@admin_required
def add_user():
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')
    if not all([username, password, role]):
        flash("Username, password, and role are required.", 'error')
        return redirect(url_for('users'))
    if role not in ['admin', 'pharmacist']:
        flash("Invalid role specified.", 'error')
        return redirect(url_for('users'))
    hashed_password = generate_password_hash(password)
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                     (username, hashed_password, role))
        conn.commit()
        log_audit(f"Admin '{session['username']}' created a new user: '{username}' with role '{role}'.")
        flash(f"User '{username}' created successfully.", 'success')
    except sqlite3.IntegrityError:
        flash(f"Username '{username}' already exists.", 'error')
    finally:
        conn.close()
    return redirect(url_for('users'))

@app.route('/users/change_role/<int:user_id>', methods=('POST',))
@login_required
@admin_required
def change_role(user_id):
    if user_id == session['user_id']:
        flash("You cannot change your own role.", 'error')
        return redirect(url_for('users'))
    new_role = request.form.get('role')
    if new_role not in ['admin', 'pharmacist']:
        flash("Invalid role specified.", 'error')
        return redirect(url_for('users'))
    conn = get_db_connection()
    user_to_change = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
    conn.commit()
    conn.close()
    log_audit(f"Admin '{session['username']}' changed role for user '{user_to_change['username']}' to '{new_role}'.")
    flash("User's role has been updated.", 'success')
    return redirect(url_for('users'))

@app.route('/users/delete/<int:user_id>', methods=('POST',))
@login_required
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        flash("You cannot delete your own account.", 'error')
        return redirect(url_for('users'))
    conn = get_db_connection()
    user_to_delete = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    if user_to_delete:
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        log_audit(f"Admin '{session['username']}' deleted user: '{user_to_delete['username']}'.")
        flash("User has been deleted.", 'success')
    else:
        flash("User not found.", 'error')
    conn.close()
    return redirect(url_for('users'))

# --- Audit Log Route ---
@app.route('/audit-log')
@login_required
@admin_required
def audit_log():
    page = request.args.get('page', 1, type=int)
    offset = (page - 1) * ITEMS_PER_PAGE
    conn = get_db_connection()
    total_items = conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    total_pages = (total_items + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE if total_items > 0 else 1
    logs = conn.execute(
        'SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?',
        (ITEMS_PER_PAGE, offset)
    ).fetchall()
    conn.close()
    return render_template('audit_log.html', logs=logs, current_page=page, total_pages=total_pages)

# --- Run the Application ---
if __name__ == '__main__':
    app.run(debug=True)
