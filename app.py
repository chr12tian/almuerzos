# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from werkzeug.security import check_password_hash as werkzeug_check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_clave_secreta_muy_segura'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3307/bd_rest'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class Usuario(db.Model):
    __tablename__ = 'Usuarios'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(50), nullable=False)

def check_password(stored_password, provided_password):
    if stored_password.startswith('$2b$') or stored_password.startswith('$2a$'):
        return bcrypt.check_password_hash(stored_password, provided_password)
    elif stored_password.startswith('pbkdf2:sha256:'):
        return werkzeug_check_password_hash(stored_password, provided_password)
    else:
        # Fallback para otros formatos de hash o contraseñas en texto plano (no recomendado)
        return stored_password == provided_password



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        usuario = Usuario.query.filter_by(email=email).first()

        if usuario and check_password(usuario.password, password):
            session['user_id'] = usuario.id
            # Verificar el rol del usuario
            if usuario.rol == 'admin':
                flash('Inicio de sesión exitoso como administrador', 'success')
                return redirect(url_for('admin'))  # Redirigir a la página admin
            else:
                flash('Inicio de sesión exitoso', 'success')
                return redirect(url_for('home'))  # Redirigir a la página home
        else:
            flash('Email o contraseña incorrectos', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        password = request.form['password']
        rol = request.form['rol']

        if Usuario.query.filter_by(email=email).first():
            flash('El email ya está en uso', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = Usuario(nombre=nombre, email=email, password=hashed_password, rol=rol)
        db.session.add(new_user)
        db.session.commit()
        flash('Usuario creado exitosamente', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/')
def home():
    if 'user_id' in session:
        return render_template('home.html')
    return redirect(url_for('login'))


@app.route('/admin')
def admin():
    if 'user_id' in session:
        return render_template('admin.html')
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Has cerrado sesión', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)