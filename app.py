from os.path import join, dirname
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import time
from bson.objectid import ObjectId
import random
import string
import os

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

# Konfigurasi MongoDB
MONGODB_URI = os.environ.get("MONGODB_URI")
DB_NAME =  os.environ.get("DB_NAME")

client = MongoClient(MONGODB_URI)

db = client[DB_NAME]

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)


# Diperlukan login dekorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        
        # Cek ketidakaktifan
        if 'last_activity' in session and time.time() - session['last_activity'] > app.config['PERMANENT_SESSION_LIFETIME'].total_seconds():
            session.clear()
            return redirect(url_for('login'))
        session['last_activity'] = time.time()

        return f(*args, **kwargs)
    return decorated_function

# Peran dekorator diperlukan
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or (session['role'] != role and session['role'] != 'admin'):
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Halaman login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = db.users.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['role'] = user['role']
            session['last_activity'] = time.time()
            session.permanent = True 
            if user['role'] == 'admin':
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('home'))
        error_message = 'Invalid username or password'
        flash('Invalid username or password')
    return render_template('page/login.html', error_message=error_message)

# Halaman loginAdmin
@app.route('/loginAdmin', methods=['GET', 'POST'])
def loginAdmin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = db.users.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('home'))
        flash('Invalid username or password')
    return render_template('admin/login.html')

# Halaman register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash("Passwords do not match.", 'error')
            return render_template('page/register.html')
        
        existing_user = db.users.find_one({'username': username})
        if existing_user:
            flash("Username already exists.", 'error')
            return render_template('page/register.html')
        
        hashed_password = generate_password_hash(password)
        user_document = {
            '_id': username,
            'username': username,
            'password': hashed_password,
            'role': 'user',
            'password_length': len(password)
        }
        
        try:
            db.users.insert_one(user_document)
            flash("Registration successful. Please log in.", 'success')
            return redirect(url_for('login'))
        except Exception as e:
            if 'duplicate key error' in str(e):
                flash("Nama pengguna sudah ada.", 'error')
            else:
                flash(f"Terjadi kesalahan: {str(e)}", 'error')
            return render_template('page/register.html')
    
    return render_template('page/register.html')

# Halaman Create Admin dan User
@app.route('/user')
@login_required
@role_required('admin')
def user():
    users = list(db.users.find())
    return render_template('admin/user/user.html', users=users, current_route=request.path)

@app.route('/checkUserName', methods=['POST'])
def check_user_name():
    data = request.json
    username = data.get('username', '')
    
    existing_user = db.users.find_one({'username': username})
    if existing_user:
        return jsonify({'exists': True})
    else:
        return jsonify({'exists': False})

@app.route('/addUser', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def addUser():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        hashed_password = generate_password_hash(password)

        user_document = {
            '_id': username,
            'username': username,
            'password': hashed_password,
            'role': role
        }

        try:
            db.users.insert_one(user_document)
        except:
            flash('Username already exists')
            return redirect(url_for('user'))

        return redirect(url_for('user'))
    return render_template('admin/user/addUser.html')

@app.route('/editUser/<_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def editUser(_id):
    user = db.users.find_one({"_id": _id})
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        password = request.form['password']

        update_fields = {
            'username': username,
            'role': role
        }

        if password:
            hashed_password = generate_password_hash(password)
            update_fields['password'] = hashed_password
            update_fields['password_length'] = len(password)

        try:
            db.users.update_one({"_id": _id}, {"$set": update_fields})
            flash("User updated successfully")
        except Exception as e:
            flash(f"An error occurred: {e}")

        return redirect(url_for('user'))

    return render_template('admin/user/editUser.html', user=user)

@app.route('/deleteUser/<_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def deleteUser(_id):
    db.users.delete_one({"_id": _id})
    return redirect(url_for("user"))


# Halaman logout
@app.route('/logoutAdmin')
def logoutAdmin():
    session.clear()
    return redirect(url_for('loginAdmin'))

@app.route('/')
def home():
    products = list(db.products.find())
    return render_template('page/home.html',products=products)

@app.route('/pageProduct')
@login_required
@role_required('user')
def pageProduct():
    products = list(db.products.find())
    return render_template('page/product.html',products=products)

@app.route('/detail/<product_id>')
@login_required
@role_required('user')
def detail(product_id):
    product = db.products.find_one({"_id": ObjectId(product_id)})
    return render_template('page/detail.html', product=product)

@app.route('/about')
def about():
    return render_template('page/about.html')

@app.route('/contact')
def contact():
    return render_template('page/kontak.html')

@app.route('/dashboard')
@login_required
@role_required('admin')
def dashboard():
    from datetime import datetime, timedelta
    import calendar

    # Data Penjualan 7 Hari Terakhir
    end_date = datetime.now()
    start_date = end_date - timedelta(days=6)

    sales_data = db.sale.find({
        'tanggal_penjualan': {
            '$gte': start_date.strftime('%d-%m-%Y'),
            '$lte': end_date.strftime('%d-%m-%Y')
        }
    })

    day_name_translation = {
        "Monday": "Senin",
        "Tuesday": "Selasa",
        "Wednesday": "Rabu",
        "Thursday": "Kamis",
        "Friday": "Jumat",
        "Saturday": "Sabtu",
        "Sunday": "Minggu"
    }
    
    month_name_translation = {
        "January": "Jan",
        "February": "Feb",
        "March": "Maret",
        "April": "April",
        "May": "Mei",
        "June": "Juni",
        "July": "Juli",
        "August": "Agust",
        "September": "Sept",
        "October": "Okt",
        "November": "Nov",
        "December": "Des"
    }

    daily_sales = {day: 0 for day in day_name_translation.values()}

    for sale in sales_data:
        sale_date = datetime.strptime(sale['tanggal_penjualan'], '%d-%m-%Y')
        day_name = sale_date.strftime('%A')
        indonesian_day_name = day_name_translation.get(day_name)
        if indonesian_day_name:
            total_amount = sum(item['total_harga'] for item in sale['items'])
            daily_sales[indonesian_day_name] += total_amount

    weekly_total = sum(daily_sales.values())
    last_day_total = daily_sales[day_name_translation[end_date.strftime('%A')]]

    sales_chart_data = []
    labels = []
    for i in range(7):
        day = (start_date + timedelta(days=i)).strftime('%A')
        indonesian_day_name = day_name_translation.get(day)
        labels.append(indonesian_day_name)
        sales_chart_data.append(daily_sales[indonesian_day_name])

    # Data Pembelian 12 Bulan Terakhir
    end_month = end_date.replace(day=1)
    start_month = (end_month - timedelta(days=365)).replace(day=1)

    purchases_data = db.purchases.find({
        'tanggal_pembelian': {
            '$gte': start_month.strftime('%d-%m-%Y'),
            '$lte': end_date.strftime('%d-%m-%Y')
        }
    })

    # Inisialisasi kamus pembelian bulanan selama 12 bulan terakhir
    monthly_purchases = {f"{end_month.year}-{str(end_month.month).zfill(2)}": 0}
    for i in range(1, 12):
        previous_month = (end_month - timedelta(days=i * 30)).replace(day=1)
        month_key = f"{previous_month.year}-{str(previous_month.month).zfill(2)}"
        monthly_purchases[month_key] = 0

    # Hitung pembelian setiap bulan
    for purchase in purchases_data:
        purchase_date = datetime.strptime(purchase['tanggal_pembelian'], '%d-%m-%Y')
        month_key = f"{purchase_date.year}-{str(purchase_date.month).zfill(2)}"
        if month_key in monthly_purchases:
            total_amount = sum(item['total_harga'] for item in purchase['items'])
            monthly_purchases[month_key] += total_amount

    # Pastikan urutan bulan sudah benar (dari terlama hingga terbaru)
    sorted_months = sorted(monthly_purchases.keys())
    purchases_chart_data = [monthly_purchases[month] for month in sorted_months]
    purchase_labels = [month_name_translation[calendar.month_name[int(month.split('-')[1])]] for month in sorted_months]

    monthly_total = sum(purchases_chart_data)
    last_month_key = f"{end_date.year}-{str(end_date.month).zfill(2)}"
    last_month_total = monthly_purchases[last_month_key]

    suppliers = db.suppliers.count_documents({})
    products = db.products.count_documents({})
    users = db.users.count_documents({"role": "user"})

    return render_template(
        'admin/dashboard.html',
        current_route=request.path,
        suppliers=suppliers,
        products=products,
        users=users,
        weekly_total=weekly_total,
        last_day_total=last_day_total,
        sales_chart_data=sales_chart_data,
        labels=labels,
        monthly_total=monthly_total,
        last_month_total=last_month_total,
        purchases_chart_data=purchases_chart_data,
        purchase_labels=purchase_labels
        )

def format_number(value):
    return "{:,.0f}".format(value)

app.jinja_env.filters['format_number'] = format_number


# Produk ###############################################################################################
# Halaman Produk ###############################################################################################
@app.route('/product')
@login_required
@role_required('admin')
def product():
    products = list(db.products.find())
    return render_template('admin/product/product.html', products=products, current_route=request.path)

@app.route('/checkProductName', methods=['POST'])
def check_product_name():
    data = request.json
    product_name = data.get('nama', '')
    
    existing_product = db.products.find_one({'nama': product_name})
    if existing_product:
        return jsonify({'exists': True})
    else:
        return jsonify({'exists': False})
    
@app.route('/addProduct', methods=['GET','POST'])
@login_required
@role_required('admin')
def addProduct():
    product_exists = False

    if request.method=='POST':
        nama = request.form['nama']
        satuan = request.form['satuan']
        harga = request.form['harga']
        deskripsi = request.form['deskripsi']
        nama_gambar = request.files['gambar']
        stok = int(request.form.get('stok', 0))

        # Periksa apakah Nama Barang dengan nama yang sama sudah ada
        existing_product = db.products.find_one({'nama': nama})
        if existing_product:
            product_exists = True
        else:
            if nama_gambar:
                nama_file_asli = nama_gambar.filename
                nama_file_gambar = nama_file_asli.split('/')[-1]
                file_path = f'static/images/imgProducts/{nama_file_gambar}'
                nama_gambar.save(file_path)
            else:
                nama_file_gambar = None
            
            doc = {
                'nama':nama,
                'gambar': nama_file_gambar,
                'satuan': satuan,
                'harga': harga,
                'deskripsi': deskripsi,
                'stok': stok
            }
            db.products.insert_one(doc)
            return redirect(url_for("product"))

    return render_template('admin/product/addProduct.html', product_exists=product_exists)

@app.route('/editProduct/<_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def editProduct(_id):
    product_exists = False

    if request.method == 'POST':
        id = request.form['_id']
        nama = request.form['nama']
        satuan = request.form['satuan']
        harga = request.form['harga']
        deskripsi = request.form['deskripsi']
        nama_gambar = request.files['gambar']
        stok = int(request.form.get('stok', 0))

        # Periksa apakah Nama Barang dengan nama yang sama sudah ada, kecuali produk yang sedang diedit
        existing_product = db.products.find_one({'nama': nama, '_id': {'$ne': ObjectId(id)}})
        if existing_product:
            product_exists = True
        else:
            doc = {
                'nama': nama,
                'satuan': satuan,
                'harga': harga,
                'deskripsi': deskripsi,
                'stok': stok
            }

            if nama_gambar:
                # Dapatkan nama file gambar lama dari database
                old_product = db.products.find_one({'_id': ObjectId(id)})
                old_image_filename = old_product.get('gambar')

                # Simpan gambar baru
                nama_file_asli = nama_gambar.filename
                nama_file_gambar = nama_file_asli.split('/')[-1]
                file_path = f'static/images/imgProducts/{nama_file_gambar}'
                nama_gambar.save(file_path)
                doc['gambar'] = nama_file_gambar

                # Hapus file gambar lama dari folder jika ada
                if old_image_filename:
                    old_image_path = os.path.join('static/images/imgProducts', old_image_filename)
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)

            db.products.update_one({"_id": ObjectId(id)}, {"$set": doc})
            return redirect(url_for("product"))

    id = ObjectId(_id)
    data = list(db.products.find({"_id": id}))
    return render_template('admin/product/editProduct.html', data=data, product_exists=product_exists)


@app.route('/deleteProduct/<_id>', methods=['GET','POST'])
@login_required
@role_required('admin')
def deleteProduct(_id):
    _id = ObjectId(_id)
    
    product_info = db.products.find_one({"_id": ObjectId(_id)})
    if product_info:
        image_path = os.path.join(app.static_folder, 'images', 'imgProducts', product_info['gambar'])
        if os.path.exists(image_path):
            os.remove(image_path)

    db.products.delete_one({"_id": ObjectId(_id)})
    return redirect(url_for("product"))

# Supplier ###############################################################################################
# Halaman Suplier ###############################################################################################
@app.route('/supplier')
@login_required
@role_required('admin')
def supplier():
    suppliers = list(db.suppliers.find())
    return render_template('admin/supplier/supplier.html', suppliers=suppliers, current_route=request.path)

@app.route('/checkSupplierName', methods=['POST'])
def check_supplier_name():
    data = request.json
    supplier_name = data.get('nama', '')
    
    existing_supplier = db.suppliers.find_one({'nama': supplier_name})
    if existing_supplier:
        return jsonify({'exists': True})
    else:
        return jsonify({'exists': False})

@app.route('/addSupplier', methods=['GET','POST'])
@login_required
@role_required('admin')
def addSupplier():
    supplier_exists = False

    if request.method=='POST':
        nama = request.form['nama']
        alamat = request.form['alamat']
        noTelp = request.form['noTelp']
        nama_gambar = request.files['gambar']

        # Periksa apakah Nama Barang dengan nama yang sama sudah ada
        existing_supplier = db.suppliers.find_one({'nama': nama})
        if existing_supplier:
            supplier_exists = True
        else:
            if nama_gambar:
                nama_file_asli = nama_gambar.filename
                nama_file_gambar = nama_file_asli.split('/')[-1]
                file_path = f'static/images/imgSuppliers/{nama_file_gambar}'
                nama_gambar.save(file_path)
            else:
                nama_file_gambar = None
            
            doc = {
                'nama':nama,
                'alamat':alamat,
                'gambar': nama_file_gambar,
                'noTelp': noTelp,
            }
            db.suppliers.insert_one(doc)
            return redirect(url_for("supplier"))

    return render_template('admin/supplier/addSupplier.html', supplier_exists=supplier_exists)

@app.route('/editSupplier/<_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def editSupplier(_id):
    supplier_exists = False

    if request.method == 'POST':
        id = request.form['_id']  
        nama = request.form['nama']
        alamat = request.form['alamat']
        noTelp = request.form['noTelp']
        nama_gambar = request.files['gambar']

        # Periksa apakah Nama Supplier dengan nama yang sama sudah ada
        existing_supplier = db.suppliers.find_one({'nama': nama, '_id': {'$ne': ObjectId(id)}})
        if existing_supplier:
            supplier_exists = True
        else:
            doc = {
                'nama': nama,
                'alamat': alamat,
                'noTelp': noTelp,
            }
            if nama_gambar:
                # Dapatkan nama file gambar lama dari database
                old_product = db.suppliers.find_one({'_id': ObjectId(id)})
                old_image_filename = old_product.get('gambar')

                # Simpan gambar baru
                nama_file_asli = nama_gambar.filename
                nama_file_gambar = nama_file_asli.split('/')[-1]
                file_path = f'static/images/imgSuppliers/{nama_file_gambar}'
                nama_gambar.save(file_path)
                doc['gambar'] = nama_file_gambar

                # Hapus file gambar lama dari folder jika ada
                if old_image_filename:
                    old_image_path = os.path.join('static/images/imgSuppliers', old_image_filename)
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)

            db.suppliers.update_one({"_id": ObjectId(id)}, {"$set": doc}) 
            return redirect(url_for("supplier"))

    id = ObjectId(_id)
    data = list(db.suppliers.find({"_id": id}))
    return render_template('admin/supplier/editSupplier.html', data=data, supplier_exists=supplier_exists)

@app.route('/deleteSupplier/<_id>', methods=['GET','POST'])
@login_required
@role_required('admin')
def deleteSupplier(_id):
    _id = ObjectId(_id)
    
    product_info = db.suppliers.find_one({"_id": ObjectId(_id)})
    if product_info:
        image_path = os.path.join(app.static_folder, 'images', 'imgSuppliers', product_info['gambar'])
        if os.path.exists(image_path):
            os.remove(image_path)

    _id = ObjectId(_id)
    db.suppliers.delete_one({"_id": ObjectId(_id)})
    return redirect(url_for("supplier"))

# Stock ###############################################################################################
# Halaman Stock ###############################################################################################
@app.route('/stock')
@login_required
@role_required('admin')
def stock():
    products = list(db.products.find())
    return render_template('admin/stock/stock.html', products=products, current_route=request.path)

def get_supplier_name(supplier_id):
    supplier = db.suppliers.find_one({'_id': ObjectId(supplier_id)})
    if supplier:
        return supplier['nama']
    else:
        return None

@app.route('/editStock/<_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def editStock(_id):
    if request.method == 'POST':
        id = ObjectId(_id)
        pengurangan = int(request.form['pengurangan'])
        keterangan = request.form['keterangan']

        # Simpan informasi pengurangan stok dan keterangan (jika ada)
        if pengurangan > 0:
            pengurangan_doc = {
                'nama_barang': db.products.find_one({'_id': id})['nama'],
                'jumlah_pengurangan': pengurangan,
                'keterangan': keterangan
            }
            db.pengurangan.insert_one(pengurangan_doc)

            # Kurangi stok di koleksi 'products'
            db.products.update_one(
                {'_id': id},
                {'$inc': {'stok': -pengurangan}}
            )

        return redirect(url_for('stock'))

    # Jika metode adalah GET, tampilkan halaman editStock.html dengan data produk yang sesuai
    id = ObjectId(_id)
    product = db.products.find_one({'_id': id})
    return render_template('admin/stock/editStock.html', product=product)


# pembelian ###############################################################################################
# Halaman pembelian ###############################################################################################
@app.route('/pembelian')
@login_required
@role_required('admin')
def pembelian():
    suppliers = list(db.suppliers.find())
    products = list(db.products.find())

    purchase_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    current_date = datetime.now().strftime("%d-%m-%Y")

    return render_template('admin/pembelian/pembelian.html', products=products, suppliers=suppliers, current_route=request.path, purchase_code=purchase_code, current_date=current_date)

@app.route('/supplier/<supplier_id>')
@login_required
@role_required('admin')
def get_supplier(supplier_id):
    supplier = db.suppliers.find_one({'_id': ObjectId(supplier_id)})
    if supplier:
        supplier['_id'] = str(supplier['_id'])
        return jsonify(supplier)
    else:
        return jsonify({'error': 'Supplier not found'}), 404

@app.route('/product/<product_id>', methods=['GET'])
def get_product_details(product_id):
    product = db.products.find_one({'_id': ObjectId(product_id)}) # type: ignore
    if product:
        return jsonify({
            '_id': str(product['_id']),
            'nama': product['nama'],
            'satuan': product['satuan'],
            'harga': product['harga'],
            'stok': product['stok'],
            'gambar': product['gambar']
        })
    else:
        return jsonify({'error': 'Product not found'}), 404

@app.route('/save_sales', methods=['POST'])
def save_sales():
    data = request.json
    try:
        for sales_code, sales_details in data.items():
            items = sales_details['items']
            for item in items:
                product = db.products.find_one({'_id': ObjectId(item['_id'])})
                if product and product['stok'] >= item['jumlah']:
                    new_stock = product['stok'] - item['jumlah']
                    db.products.update_one(
                        {'_id': ObjectId(item['_id'])},
                        {'$set': {'stok': new_stock}}
                    )
                else:
                    return jsonify({'error': 'Stock exceeded for product: ' + item['produk']}), 400

        db.sales.insert_one(data)
        return jsonify({'success': 'Sales saved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/addPembelian', methods=['POST'])
def addPembelian():
    try:
        data = request.json
        pembelian = data.get('pembelian', [])

        for pembelian_item in pembelian:
            pembelian_item['tanggal_pembelian'] = datetime.strptime(pembelian_item['tanggal_pembelian'], '%Y-%m-%d').strftime('%d-%m-%Y')
            for item in pembelian_item['items']:
                item['harga'] = int(item['harga'])
                item['jumlah'] = int(item['jumlah'])
                item['total_harga'] = int(item['total_harga'])

                if 'satuan' not in item:
                    product_id = item['_id']
                    product = db.products.find_one({"_id": ObjectId(product_id)})
                    if product:
                        item['satuan'] = product.get('satuan', 'undefined')

                product_id = item['_id']
                product = db.products.find_one({"_id": ObjectId(product_id)})
                if product:
                    new_stock = product['stok'] + item['jumlah']
                    db.products.update_one(
                        {"_id": ObjectId(product_id)},
                        {"$set": {"stok": new_stock}}
                    )

        db.purchases.insert_many(pembelian)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# penjualan ###############################################################################################
# Halaman penjualan ###############################################################################################
@app.route('/penjualan')
@login_required
@role_required('admin')
def penjualan():
    products = list(db.products.find())
    purchase_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    current_date = datetime.now().strftime("%d-%m-%Y")
    return render_template('admin/penjualan/penjualan.html', products=products, current_route=request.path, purchase_code=purchase_code, current_date=current_date)

    
@app.route('/addPenjualan', methods=['POST'])
def addPenjualan():
    try:
        data = request.json
        penjualan = data.get('penjualan', [])

        for penjualan_item in penjualan:
            penjualan_item['tanggal_penjualan'] = datetime.strptime(penjualan_item['tanggal_penjualan'], '%Y-%m-%d').strftime('%d-%m-%Y')
            for item in penjualan_item['items']:
                item['harga'] = int(item['harga'])
                item['jumlah'] = int(item['jumlah'])
                item['total_harga'] = int(item['total_harga'])

                if 'satuan' not in item:
                    product_id = item['_id']
                    product = db.products.find_one({"_id": ObjectId(product_id)})
                    if product:
                        item['satuan'] = product.get('satuan', 'undefined')

                product_id = item['_id']
                product = db.products.find_one({"_id": ObjectId(product_id)})
                if product:
                    new_stock = product['stok'] - item['jumlah']
                    db.products.update_one(
                        {"_id": ObjectId(product_id)},
                        {"$set": {"stok": new_stock}}
                    )

        db.sale.insert_many(penjualan)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
