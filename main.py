import base64
import codecs
import io
import hashlib
import math
import secrets
import cv2
import numpy
import numpy as np
import time
import os

from flask import Flask, render_template, url_for, flash, redirect, request, jsonify
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from functools import wraps
from forms import LoginForm, SignUpForm, AdminLoginForm, AdminSignUpForm, AddPatientForm, PatientLoginForm, \
    UpdatePatientPasswordForm, RevealImageForm, UpdateUserPasswordForm
from password_strength import PasswordPolicy
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, SubmitField, DateField, SelectField
from wtforms.validators import DataRequired
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from tkinter.filedialog import *
from Crypto import Random
from PIL import Image
from deepStega import hideImageFunc, revealImageFunc

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = '661476085b7a9f1ba6cb8e39f3368391'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Ap411738Cd./@localhost/users'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# initialize the database
mydb = SQLAlchemy(app)

# initialize the login manager
login_manager = LoginManager(app)
login_manager.session_protection = "strong"

# initialize the bcrypt
bcrypt = Bcrypt(app)


@login_manager.user_loader
def load_user(user_id):
    return Employees.query.get(int(user_id)) or Admin.query.get(int(user_id)) or Patients.query.get(int(user_id))


def login_required(role="ANY"):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if (current_user.urole != role) and (role != "ANY"):
                return login_manager.unauthorized()
            return fn(*args, **kwargs)

        return decorated_view

    return wrapper


# create model
class Admin(mydb.Model, UserMixin):
    id = mydb.Column(mydb.Integer, primary_key=True)
    name = mydb.Column(mydb.String(20), nullable=False)
    adminID = mydb.Column(mydb.String(10), unique=True, nullable=False)
    email = mydb.Column(mydb.String(50), unique=True, nullable=False)
    salt = mydb.Column(mydb.String(256), nullable=False)
    password = mydb.Column(mydb.String(256), nullable=False)
    urole = mydb.Column(mydb.String(80), default="Admin")

    def __init__(self, name, adminID, email, salt, password, urole):
        self.name = name
        self.adminID = adminID
        self.email = email
        self.salt = salt
        self.password = password
        self.urole = urole

    def get_id(self):
        return self.id

    def get_adminID(self):
        return self.adminID

    def get_email(self):
        return self.email

    def get_urole(self):
        return self.urole

    # create a string
    def __repr__(self):
        return f"User('{self.id}','{self.name}','{self.adminID}','{self.email}','{self.password}, {self.urole}')"


class Employees(mydb.Model, UserMixin):
    id = mydb.Column(mydb.Integer, primary_key=True)
    name = mydb.Column(mydb.String(20), nullable=False)
    employeeID = mydb.Column(mydb.String(10), unique=True, nullable=False)
    email = mydb.Column(mydb.String(50), unique=True, nullable=False)
    phone = mydb.Column(mydb.String(11), nullable=False)
    department = mydb.Column(mydb.String(20), nullable=False)
    occupation = mydb.Column(mydb.String(20), nullable=False)
    ic = mydb.Column(mydb.String(20), nullable=False)
    gender = mydb.Column(mydb.String(20), nullable=False)
    salt = mydb.Column(mydb.String(256), nullable=False)
    password = mydb.Column(mydb.String(256), nullable=False)
    changePwd = mydb.Column(mydb.Boolean, default=False)
    urole = mydb.Column(mydb.String(80), default="Employee")

    encryption_details = mydb.relationship('Encryption', back_populates='physician_details')

    def __init__(self, name, employeeID, email, phone, department, occupation, ic, gender, salt, password, changePwd,
                 urole):
        self.name = name
        self.employeeID = employeeID
        self.email = email
        self.phone = phone
        self.department = department
        self.occupation = occupation
        self.ic = ic
        self.gender = gender
        self.salt = salt
        self.password = password
        self.changePwd = changePwd
        self.urole = urole

    def get_id(self):
        return self.id

    def get_patientID(self):
        return self.patientID

    def get_email(self):
        return self.email

    def get_changePwd(self):
        return self.changePwd

    def get_urole(self):
        return self.urole

    # create a string
    def __repr__(self):
        return f"Employee('{self.id}','{self.name}','{self.employeeID}','{self.email}','{self.phone}','{self.department}','{self.occupation}','{self.password}')"


class Patients(mydb.Model, UserMixin):
    id = mydb.Column(mydb.Integer, primary_key=True)
    name = mydb.Column(mydb.String(45), nullable=False)
    patientID = mydb.Column(mydb.String(10), unique=True, nullable=False)
    email = mydb.Column(mydb.String(50), unique=True, nullable=False)
    phone = mydb.Column(mydb.String(11), nullable=False)
    ic = mydb.Column(mydb.String(20), nullable=False)
    born_date = mydb.Column(mydb.DateTime, nullable=False)
    gender = mydb.Column(mydb.String(10), nullable=False)
    salt = mydb.Column(mydb.String(256), nullable=False)
    password = mydb.Column(mydb.String(256), nullable=False)
    changePwd = mydb.Column(mydb.Boolean, default=False)
    urole = mydb.Column(mydb.String(80), default="Patient")

    medical_history = mydb.relationship('Encryption', back_populates='patient_details')

    def __init__(self, name, patientID, email, phone, ic, born_date, gender, salt, password, changePwd, urole):
        self.name = name
        self.patientID = patientID
        self.email = email
        self.phone = phone
        self.ic = ic
        self.born_date = born_date
        self.gender = gender
        self.salt = salt
        self.password = password
        self.changePwd = changePwd
        self.urole = urole

    def get_id(self):
        return self.id

    def get_patientID(self):
        return self.patientID

    def get_email(self):
        return self.email

    def get_changePwd(self):
        return self.changePwd

    def get_urole(self):
        return self.urole

    # create a string
    def __repr__(self):
        return f"Patient('{self.id}','{self.name}','{self.patientID}','{self.email}','{self.phone}','{self.ic}','{self.born_date}','{self.gender}')"


class Encryption(mydb.Model):
    image_id = mydb.Column(mydb.Integer, primary_key=True)
    encrypted_medical_image = mydb.Column(mydb.BLOB, nullable=False)
    patient_id = mydb.Column(mydb.String(45), mydb.ForeignKey('patients.patientID'), nullable=False)
    patient_name = mydb.Column(mydb.String(50), nullable=False)
    department = mydb.Column(mydb.String(20), nullable=False)
    image_title = mydb.Column(mydb.String(100), nullable=False)
    image_category = mydb.Column(mydb.String(50), nullable=False)
    date_of_creation = mydb.Column(mydb.DateTime, nullable=False)
    rsa_public = mydb.Column(mydb.String(500), nullable=False)
    aes_encrypted_key = mydb.Column(mydb.BLOB, nullable=False)
    nonce = mydb.Column(mydb.BLOB, nullable=False)
    tag = mydb.Column(mydb.BLOB, nullable=False)
    physician_name = mydb.Column(mydb.String(50), nullable=False)
    physician_id = mydb.Column(mydb.String(10), mydb.ForeignKey('employees.employeeID'), nullable=False)

    physician_details = mydb.relationship('Employees', back_populates="encryption_details")
    patient_details = mydb.relationship('Patients', back_populates="medical_history")

    # create a string
    def __repr__(self):
        return f"Conversion('{self.image_id}','{self.encrypted_medical_image}','{self.patient_name}','{self.department}','{self.image_title}','{self.image_category}'," \
               f"'{self.date_of_creation}','{self.rsa_public}','{self.aes_encrypted_key}','{self.nonce}','{self.tag}','{self.physician_name}','{self.physician_id}')"


class ConversionForm(FlaskForm):
    medical_image_file = FileField('Medical Image', validators=[FileRequired(), FileAllowed(['png', 'jpg', 'jpeg'],
                                                                                            message='We only accept JPG, JPEG or PNG file')])
    name = StringField('Patient Name', validators=[DataRequired()])
    patient_id = SelectField('Patient ID', choices=[])
    department = StringField('Department', validators=[DataRequired()])
    physician_name = StringField('Physician Name')
    physician_id = SelectField('Physician ID', choices=[])
    title = StringField('Title', validators=[DataRequired()])
    category = SelectField('Category', choices=[('X-Rays', 'X-Rays'), ('Ultrasound', 'Ultrasound'), ('CT', 'CT scans'),
                                                ('MRI', 'MRI')])
    date = DateField('Date of creation', format='%Y-%m-%d')
    submit = SubmitField('Save to Database')


# set policy for password
policy = PasswordPolicy.from_names(
    length=8,
    uppercase=1,
    numbers=1,
    special=2,
)


@app.route("/", methods=['GET', 'POST'], endpoint='login_selection')
@app.route("/login_selection", methods=['GET', 'POST'])
def login_selection():
    logout_user()
    return render_template('login_selection.html', title='Login')


@app.route("/admin_login", methods=['GET', 'POST'], endpoint='admin_login')
def admin_login():
    form = AdminLoginForm()

    if form.validate_on_submit():
        # check whether the user is existed
        administrative = Admin.query.filter_by(adminID=form.adminID.data).first()
        # if the user is existed
        if administrative:
            # get the password and hash the password with salt
            admin_pwd = form.password.data.encode()
            get_admin_hash = hashlib.pbkdf2_hmac('sha256', admin_pwd, bytes.fromhex(administrative.salt), 10000)
            hex_hash = get_admin_hash.hex()

            # compare the hashed password with the particular user password that stored in db
            if hex_hash == administrative.password:
                login_user(administrative, remember=False, duration=None, force=False, fresh=True)
                return redirect(url_for('sign_up'))
            else:
                flash('Login Unsuccessful. Password is invalid, please check your password', 'danger')

        # if the user is not existed
        else:
            flash('This admin is not existed! Please check your admin ID', 'danger')
            return render_template('admin_login.html', title='admin_login', form=form)

    return render_template('admin_login.html', title='admin_login', form=form)


@app.route("/adminSignUp", methods=['GET', 'POST'], endpoint='admin_signUp')
def admin_signUp():
    if current_user.is_authenticated:
        return redirect(url_for('sign_up'))

    form = AdminSignUpForm()
    # get input password data
    password = form.confirmed_password.data

    if form.validate_on_submit():
        # check whether there is any input in password field
        # if there is an input
        if password is not None:
            # check whether the password matched with the password policy
            check_policy = policy.test(password)
            # if it is not matched
            if check_policy:
                flash(f'Password not strong enough. '
                      f'Your password must contain at least 8 characters with at least one number, '
                      f'one uppercase and lowercase letter, and 2 special characters', 'info')
                return render_template('admin_signUp.html', title='adminSignUp', form=form)

            # if it is matched
            else:
                # check whether the employee ID had been set up
                admin = Admin.query.filter_by(adminID=form.adminID.data).first()
                # if the employee ID is not being used
                if admin is None:
                    # generate a random salt for password
                    salt = os.urandom(32)
                    # get user input for password
                    user_pwd = form.confirmed_password.data.encode()
                    # hash the password with salt
                    hashed_password = hashlib.pbkdf2_hmac('sha256', user_pwd, salt, 100000)
                    # convert the hashed password to hex
                    hex_hash = hashed_password.hex()
                    # convert the salt to hex
                    hex_salt = salt.hex()

                    # add user details into db
                    admin = Admin(name=form.name.data, adminID=form.adminID.data, email=form.email.data,
                                  salt=hex_salt, password=hex_hash, urole="Admin")
                    mydb.session.add(admin)
                    mydb.session.commit()

                    login_user(admin, remember=False, duration=None, force=False, fresh=True)
                    flash(f'Account created for {form.adminID.data}', 'success')
                    return redirect(url_for('sign_up'))

                # if the employee ID had been used
                else:
                    flash(f'This admin ID is taken!', 'danger')
                    return render_template('admin_signUp.html', title='adminSignUp', form=form)

    return render_template('admin_signUp.html', title='adminSignUp', form=form)


@app.route("/login", methods=['GET', 'POST'], endpoint='login')
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # check whether the user is existed
        user = Employees.query.filter_by(employeeID=form.employeeID.data).first()
        # if the user is existed
        if user:
            # get the password and hash the password with salt
            user_pwd = form.password.data.encode()
            get_user_hash = hashlib.pbkdf2_hmac('sha256', user_pwd, bytes.fromhex(user.salt), 10000)
            hex_hash = get_user_hash.hex()

            # compare the hashed password with the particular user password that stored in db
            if hex_hash == user.password:
                if user.changePwd:
                    login_user(user, remember=False, duration=None, force=False, fresh=True)
                    return redirect(url_for('home'))
                else:
                    return redirect(url_for('updateUserPassword'))
            else:
                flash('Login Unsuccessful. Password is invalid, please check your password', 'danger')

        # if the user is not existed
        else:
            flash('This user is not existed! Please check your employee ID', 'danger')
            return render_template('login.html', title='Login', form=form)

    return render_template('login.html', title='Login', form=form)


@app.route("/signUp", methods=['GET', 'POST'], endpoint='sign_up')
@login_required(role="Admin")
def sign_up():
    form = SignUpForm()

    if form.validate_on_submit():
        # check whether the employee ID had been set up
        user = Employees.query.filter_by(employeeID=form.employeeID.data).first()
        # if the employee ID is not being used
        if user is None:
            # generate a random salt for password
            salt = os.urandom(32)
            # get user input for password
            user_pwd = form.ic.data.encode()
            # hash the password with salt
            hashed_password = hashlib.pbkdf2_hmac('sha256', user_pwd, salt, 10000)
            # convert the hashed password to hex
            hex_hash = hashed_password.hex()
            # convert the salt to hex
            hex_salt = salt.hex()

            # add user details into db
            user = Employees(name=form.name.data, employeeID=form.employeeID.data, email=form.email.data,
                             phone=form.mobileNumber.data, department=form.department.data,
                             occupation=form.occupation.data,
                             ic=form.ic.data, gender=form.gender.data, salt=hex_salt, password=hex_hash,
                             changePwd=False, urole="Employee")
            mydb.session.add(user)
            mydb.session.commit()

            flash(f'Account created for {form.employeeID.data}', 'success')
            form.name.data = ""
            form.employeeID.data = ""
            form.email.data = ""
            form.mobileNumber.data = ""
            form.department.data = ""
            form.occupation.data = ""
            form.ic.data = ""
            form.gender.data = ""
            return render_template('signUp.html', title='signUp', form=form)

        # if the employee ID had been used
        if user:
            flash(f'This employee ID is taken!', 'danger')
            return render_template('signUp.html', title='signUp', form=form)

    return render_template('signUp.html', title='signUp', form=form)


@app.route("/updateUserPassword", methods=['GET', 'POST'], endpoint='updateUserPassword')
def updateUserPassword():
    form = UpdateUserPasswordForm()
    if form.validate_on_submit():
        if form.password.data == form.confirmedPassword.data:
            # check whether the user is existed
            user = Employees.query.filter_by(employeeID=form.employeeID.data).first()
            # if the user is existed
            if user:
                # generate a random salt for password
                salt = os.urandom(32)
                # get user input for password
                user_pwd = form.confirmedPassword.data.encode()
                # hash the password with salt
                hashed_password = hashlib.pbkdf2_hmac('sha256', user_pwd, salt, 100000)
                # convert the hashed password to hex
                hex_hash = hashed_password.hex()
                # convert the salt to hex
                hex_salt = salt.hex()

                Employee_data = Employees.query.filter_by(employeeID=form.employeeID.data).first()
                Employee_data.salt = hex_salt
                Employee_data.password = hex_hash
                Employee_data.changePwd = True
                mydb.session.commit()

                flash('Password Updated Successfully!!', 'info')
                login_user(user, remember=False, duration=None, force=False, fresh=True)
                return redirect(url_for('home'))
            # if the user is not existed
            else:
                flash('This user is not existed! Please check your employee ID', 'danger')
                return render_template('updateUserPassword.html', title='updateUserPassword', form=form)

        else:
            flash('Password and confirmed Password must be matched', 'danger')
    return render_template('updateUserPassword.html', title='updateUserPassword', form=form)


@app.route("/addPatient", methods=['GET', 'POST'], endpoint='addPatient')
@login_required(role="Employee")
def addPatient():
    form = AddPatientForm()

    if form.validate_on_submit():
        # check whether the patient ID had been set up
        patient_info = Patients.query.filter_by(patientID=form.patientID.data).first()
        # if the employee ID is not being used
        if patient_info is None:
            # generate a random salt for password
            salt = os.urandom(32)
            # get user input for password
            patient_pwd = form.ic.data.encode()
            # hash the password with salt
            hashed_password = hashlib.pbkdf2_hmac('sha256', patient_pwd, salt, 100000)
            # convert the hashed password to hex
            hex_hash = hashed_password.hex()
            # convert the salt to hex
            hex_salt = salt.hex()

            # add patient details into db
            patient_info = Patients(name=form.name.data, patientID=form.patientID.data, email=form.email.data,
                                    phone=form.mobileNumber.data, ic=form.ic.data,
                                    born_date=form.born_date.data, gender=form.gender.data, salt=hex_salt,
                                    password=hex_hash, changePwd=False, urole="Patient")
            mydb.session.add(patient_info)
            mydb.session.commit()

            flash(f'Add {form.patientID.data} successfully', 'success')
            form.name.data = ""
            form.patientID.data = ""
            form.email.data = ""
            form.mobileNumber.data = ""
            form.ic.data = ""
            form.born_date.data = ""
            form.gender.data = ""
            return render_template('addPatient.html', title='addPatient', form=form)

        # if the patient ID had been used
        else:
            flash(f'This patient is existed!', 'danger')
            return render_template('addPatient.html', title='addPatient', form=form)

    return render_template('addPatient.html', title='addPatient', form=form)


@app.route("/patient_login", methods=['GET', 'POST'], endpoint='patient_login')
def patient_login():
    form = PatientLoginForm()
    if form.validate_on_submit():
        # check whether the user is existed
        patient_identity = Patients.query.filter_by(patientID=form.patientID.data).first()

        # if the user is existed
        if patient_identity:
            # get the password and hash the password with salt
            patient_pwd = form.password.data.encode()
            get_patient_hash = hashlib.pbkdf2_hmac('sha256', patient_pwd, bytes.fromhex(patient_identity.salt), 10000)
            hex_hash = get_patient_hash.hex()

            # compare the hashed password with the particular user password that stored in db
            if hex_hash == patient_identity.password:
                if patient_identity.changePwd:
                    login_user(patient_identity, remember=False, duration=None, force=False, fresh=True)
                    return redirect(url_for('medicalRecords'))
                else:
                    return redirect(url_for('updatePassword'))
            else:
                flash('Login Unsuccessful. Password is invalid, please check your password', 'danger')

        # if the user is not existed
        else:
            flash('This user is not existed! Please check your patient ID', 'danger')
            return render_template('patient_login.html', title='patient_login', form=form)
    return render_template('patient_login.html', title='patient_login', form=form)


@app.route("/updatePassword", methods=['GET', 'POST'], endpoint='updatePassword')
def updatePatientPassword():
    form = UpdatePatientPasswordForm()
    if form.validate_on_submit():
        if form.password.data == form.confirmedPassword.data:
            # check whether the user is existed
            patient_identity = Patients.query.filter_by(patientID=form.patientID.data).first()
            # if the user is existed
            if patient_identity:
                # generate a random salt for password
                salt = os.urandom(32)
                # get user input for password
                patient_pwd = form.confirmedPassword.data.encode()
                # hash the password with salt
                hashed_password = hashlib.pbkdf2_hmac('sha256', patient_pwd, salt, 10000)
                # convert the hashed password to hex
                hex_hash = hashed_password.hex()
                # convert the salt to hex
                hex_salt = salt.hex()

                Patient_data = Patients.query.filter_by(patientID=form.patientID.data).first()
                Patient_data.salt = hex_salt
                Patient_data.password = hex_hash
                Patient_data.changePwd = True
                mydb.session.commit()

                flash('Password Updated Successfully!!', 'info')
                login_user(patient_identity, remember=False, duration=None, force=False, fresh=True)
                return redirect(url_for('medicalRecords'))
            # if the user is not existed
            else:
                flash('This user is not existed! Please check your patient ID', 'danger')
                return render_template('updatePassword.html', title='updatePassword', form=form)

        else:
            flash('Password and confirmed Password must be matched', 'danger')
    return render_template('updatePassword.html', title='updatePassword', form=form)


@app.route("/medicalRecords", methods=['GET', 'POST'], endpoint='medicalRecords')
@login_required(role="Patient")
def medicalRecords():
    if current_user.is_authenticated:
        patient_records = Patients.query.filter(Patients.patientID == current_user.patientID).all()
        medical_records = mydb.session.query(Employees, Encryption).join(Employees).filter(
            Encryption.patient_id == current_user.patientID).order_by(Encryption.image_id).all()
    return render_template('medicalRecords.html', title='medicalRecords', patient_records=patient_records,
                           medical_records=medical_records)


@app.route('/physician_name/<get_physician_employeeID>')
def physician(get_physician_employeeID):
    physician_name = Employees.query.filter_by(employeeID=get_physician_employeeID).all()
    physicianArray = []
    for physician in physician_name:
        physicianObj = {}
        physicianObj['id'] = physician.id
        physicianObj['name'] = physician.name
        physicianObj['employeeID'] = physician.employeeID
        physicianObj['department'] = physician.department
        physicianArray.append(physicianObj)
    return jsonify({'physicianlist': physicianArray})


@app.route('/patient_name/<get_patient_patientID>')
def patient(get_patient_patientID):
    patient_name = Patients.query.filter_by(patientID=get_patient_patientID).all()
    patientArray = []
    for patient in patient_name:
        patientObj = {}
        patientObj['id'] = patient.id
        patientObj['name'] = patient.name
        patientObj['patientID'] = patient.patientID
        patientArray.append(patientObj)
    return jsonify({'patientlist': patientArray})


@app.route("/home", methods=['GET', 'POST'], endpoint='home')
@login_required(role="Employee")
def home():
    form = ConversionForm()

    form.patient_id.choices = ['Please select a patient'] + [g.patientID for g in Patients.query.all()]

    if current_user.occupation == 'Doctor':
        form.physician_id.choices = ['Please select a physician'] + [g.employeeID for g in Employees.query.filter(
            Employees.name == current_user.name).all()]
    elif current_user.occupation == 'Nurse':
        form.physician_id.choices = ['Please select a physician'] + [g.employeeID for g in
                                                                     Employees.query.filter(
                                                                         Employees.occupation == 'Doctor').filter(
                                                                         Employees.department == current_user.department).all()]

    if request.method == 'POST':
        result = Employees.query.filter_by(employeeID=form.physician_id.data).first()
        form.physician_name.data = result.name
        form.department.data = result.department
        patientData = Patients.query.filter_by(patientID=form.patient_id.data).first()
        form.name.data = patientData.name

    if form.validate_on_submit():
        if 'medical_image_file' in request.files:
            photo = request.files['medical_image_file']
            if photo.filename != '':
                # get user uploaded image data and encrypt it
                image_data = request.files['medical_image_file'].read()
                image = base64.b64encode(image_data)

                key = secrets.token_bytes(32)
                print(key.hex())
                cipher = AES.new(key, AES.MODE_GCM)
                nonce = cipher.nonce

                start_time = time.time()
                # encrypted_image = cipher.encrypt(pad(image, 16))
                encrypted_image, tag = cipher.encrypt_and_digest(image)
                # print(encrypted_image)
                print("--- %s seconds ---" % (time.time() - start_time))

                random_generator = Random.new().read
                keyPair = RSA.generate(2048, random_generator)
                privateKey, publicKey = keyPair, keyPair.public_key()
                print("Public: ", publicKey)

                rsa_cipher = PKCS1_OAEP.new(publicKey)
                encryptedKey = rsa_cipher.encrypt(key)
                print("Encrypted: ", encryptedKey.hex())

                num_bytes = len(encrypted_image)
                num_pixels = int((num_bytes + 2) / 3)  # 3 bytes per pixel
                W = H = int(math.ceil(num_pixels ** 0.5))

                imagedata = encrypted_image + b'\0' * (W * H * 3 - len(encrypted_image))
                home = os.path.expanduser("~")
                save_path = os.path.join(home, "Downloads")
                image = Image.frombytes('RGB', (W, H), imagedata)  # create image
                image.save(save_path + "/encryptedImage.png")

                # add user details into db
                image = Encryption(encrypted_medical_image=encrypted_image, patient_name=form.name.data,
                                   patient_id=form.patient_id.data,
                                   department=form.department.data, image_title=form.title.data,
                                   image_category=form.category.data,
                                   date_of_creation=form.date.data, rsa_public=publicKey,
                                   aes_encrypted_key=encryptedKey, nonce=nonce, tag=tag,
                                   physician_name=form.physician_name.data, physician_id=form.physician_id.data)
                mydb.session.add(image)
                mydb.session.commit()
                mydb.session.flush()
                print(image.image_id)

                folder_name = image.department
                # folder_name_2 = 'CheckPublic'
                print(folder_name)
                folder = os.path.join("C:/Users/User/Documents/FYP_Program", folder_name)
                # folder_2 = os.path.join("C:/Users/User/Documents/FYP_Program", folder_name_2)
                print(folder)
                if not os.path.exists(folder):
                    os.makedirs(folder)
                # if not os.path.exists(folder_2):
                #     os.makedirs(folder_2)
                new_file = f'{image.image_id}.pem'

                f = open(os.path.join(folder, new_file), 'wb')
                f.write(privateKey.exportKey('PEM'))

                # f = open(os.path.join(folder_2, new_file), 'wb')
                # f.write(publicKey.exportKey('PEM'))
                f.close()

                form.medical_image_file.data = ""
                form.patient_id.data = ""
                form.name.data = ""
                form.department.data = ""
                form.physician_name.data = ""
                form.physician_id.data = ""
                form.title.data = ""
                form.category.data = ""
                form.date.data = ""

                flash(f'Image uploaded and saved successfully', 'info')
                print("--- %s seconds ---" % (time.time() - start_time))

                return render_template('home.html', filestring=image, form=form)

    return render_template('home.html', title='home', form=form)


@app.route("/review", methods=['GET', 'POST'], endpoint='review')
@login_required(role="Employee")
def review():
    if current_user.is_authenticated:
        if current_user.occupation == 'Nurse':
            image_data = mydb.session.query(Employees, Encryption).join(Employees).filter(
                Encryption.department == current_user.department).order_by(Encryption.image_id).all()
        elif current_user.occupation == 'Doctor':
            image_data = mydb.session.query(Employees, Encryption).join(Employees).filter(
                Encryption.physician_name == current_user.name).order_by(Encryption.image_id).all()
    return render_template('review.html', title='review', images=image_data)


@app.route("/decrypt", methods=['GET', 'POST'], endpoint='decrypt')
@login_required(role="Employee")
def decrypt():
    form = ConversionForm()

    if request.method == 'POST':
        image_data = request.form.get('image_id')
        key_data = mydb.session.query(Encryption).filter(Encryption.image_id == image_data).first()

        # get the keyfile directory
        folder_name = key_data.department
        folder = os.path.join('C:/Users/User/Documents/FYP_Program', folder_name)
        filename = f'{key_data.image_id}.pem'

        # decrypt process
        f = open(os.path.join(folder, filename), 'rb')
        privateKey = RSA.importKey(f.read())
        rsa_decrypt_cipher = PKCS1_OAEP.new(privateKey)
        decrypted_key = rsa_decrypt_cipher.decrypt(key_data.aes_encrypted_key)
        decrypt_cipher = AES.new(decrypted_key, AES.MODE_CBC, key_data.iv)
        decrypt_msg = unpad(decrypt_cipher.decrypt(key_data.encrypted_medical_image), 16)
        decode_decrypt_msg = codecs.decode(decrypt_msg, 'utf-8')

        start_time = time.time()
        b64_decode_img = base64.b64decode(decode_decrypt_msg)
        decrypted_img = Image.open(io.BytesIO(b64_decode_img))
        save_path = asksaveasfilename()
        decrypted_img.save(save_path + ".png")

        print(decode_decrypt_msg)
        print("--- %s seconds ---" % (time.time() - start_time))
    return redirect(url_for('review'))


@app.route("/reviewStaff", methods=['GET', 'POST'], endpoint='staffDB')
@login_required(role="Admin")
def staffDB():
    if current_user.is_authenticated:
        staff_data = Employees.query.all()
    return render_template('staffDB.html', title='staffDB', staffs=staff_data)


@app.route("/update", methods=['GET', 'POST'], endpoint='update')
@login_required(role="Admin")
def update():
    if request.method == 'POST':
        employee_data = Employees.query.get(request.form.get('getId'))
        employee_data.email = request.form['email']
        employee_data.phone = request.form['phone']
        employee_data.department = request.form['department']
        mydb.session.commit()
        flash('Employee Information Updated Successfully', 'info')

        return redirect(url_for('staffDB'))


@app.route("/delete/<id>", methods=['GET', 'POST'], endpoint='delete')
@login_required(role="Admin")
def delete(id):
    employee_data = Employees.query.get(id)
    mydb.session.delete(employee_data)
    mydb.session.commit()
    flash('Employee Deleted Successfully', 'info')

    return redirect(url_for('staffDB'))


@app.route("/updatePatient", methods=['GET', 'POST'], endpoint='updatePatient')
@login_required(role="Patient")
def updatePatient():
    if request.method == 'POST':
        patient_data = Patients.query.get(request.form.get('getId'))
        patient_data.email = request.form['email']
        patient_data.phone = request.form['phone']
        mydb.session.commit()
        flash('Personal Information Updated Successfully', 'info')

        return redirect(url_for('medicalRecords'))


@app.route('/patientInfo/<patient_id>', methods=['GET', 'POST'], endpoint='patientInfo')
@login_required(role="Employee")
def patientInfo(patient_id):
    form = ConversionForm()

    patient_data = Patients.query.filter(Patients.patientID == patient_id).all()
    patient_record = mydb.session.query(Employees, Encryption).join(Employees).filter(
        Encryption.patient_id == patient_id).order_by(Encryption.image_id).all()
    return render_template('patientInfo.html', title='patientInfo', patient_data=patient_data,
                           patient_record=patient_record, form=form)


@app.route("/deepSteganography", methods=['GET', 'POST'], endpoint='deepSteganography')
def deepSteganography():
    if request.method == 'POST':
        secret_data = request.form.get('image_id')
        key_data = mydb.session.query(Encryption).filter(Encryption.image_id == secret_data).first()

        # get the keyfile directory
        folder_name = key_data.department
        folder = os.path.join('C:/Users/User/Documents/FYP_Program', folder_name)
        filename = f'{key_data.image_id}.pem'

        # decrypt process
        f = open(os.path.join(folder, filename), 'rb')
        privateKey = RSA.importKey(f.read())
        print(privateKey)
        rsa_decrypt_cipher = PKCS1_OAEP.new(privateKey)
        decrypted_key = rsa_decrypt_cipher.decrypt(key_data.aes_encrypted_key)
        print(decrypted_key)

        cipher = AES.new(decrypted_key, AES.MODE_GCM, nonce=key_data.nonce)
        start_time = time.time()
        decrypt_msg = cipher.decrypt_and_verify(key_data.encrypted_medical_image, key_data.tag)
        print("--- %s seconds(aes) ---" % (time.time() - start_time))
        decode_decrypt_msg = codecs.decode(decrypt_msg, 'utf-8')
        b64_decode_img = base64.b64decode(decode_decrypt_msg)
        decrypted_img = Image.open(io.BytesIO(b64_decode_img))

        home = os.path.expanduser("~")
        save_path = os.path.join(home, "Downloads")
        decrypted_img.save(save_path + "/decryptedImage.png")

        image_np = np.array(decrypted_img)
        gray = cv2.cvtColor(image_np, cv2.COLOR_BGR2GRAY)
        img2 = np.zeros_like(image_np)
        img2[:, :, 0] = gray
        img2[:, :, 1] = gray
        img2[:, :, 2] = gray

        cover = cv2.imdecode(numpy.fromstring(request.files['cover_image'].read(), numpy.uint8),
                             cv2.IMREAD_UNCHANGED)
        coverImage = cv2.resize(cover, (256, 256))

        start_time_2 = time.time()
        hideImageFunc(img2, coverImage)
        print("--- %s seconds(deep) ---" % (time.time() - start_time_2))
        # decrypt_cipher = AES.new(decrypted_key, AES.MODE_GCM, key_data.iv)
        # # decrypt_msg = unpad(decrypt_cipher.decrypt(key_data.encrypted_medical_image), 16)
        # decrypt_msg = decrypt_cipher.decrypt(key_data.encrypted_medical_image)

    if current_user.urole == "Employee":
        flash(f'The medical image is downloaded in Download folder, please reveal your image using Reveal page!', 'info')
        return redirect(url_for('review'))
    elif current_user.urole == "Patient":
        flash(f'The medical image is downloaded in Download folder, please reveal your image using Reveal page!', 'info')
        return redirect(url_for('medicalRecords'))


@app.route("/revealImage", methods=['GET', 'POST'], endpoint='revealImage')
def revealImage():
    form = RevealImageForm()
    if form.validate_on_submit():
        if 'reveal_image_file' in request.files:
            reveal = cv2.imdecode(numpy.fromstring(request.files['reveal_image_file'].read(), numpy.uint8),
                                  cv2.IMREAD_UNCHANGED)
            revealImageFunc(reveal)
            flash(f'Revealed successfully, the medical image is downloaded in Download folder!', 'info')
    return render_template('revealImage.html', title='revealImage', form=form)


@app.route("/logout", endpoint='logout')
def logout():
    logout_user()
    return redirect(url_for('login_selection'))


if __name__ == '__main__':
    app.run(debug=True)
