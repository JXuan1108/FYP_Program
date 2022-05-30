import base64
import codecs
import io
import hashlib
import secrets
from email.mime.image import MIMEImage

import cv2

import aes
import time
import compressor
# import rsa
import os
import warnings
import torch.nn.init as init
import email
import smtplib
import ssl

from flask import Flask, render_template, url_for, flash, redirect, request, jsonify, current_app
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from functools import wraps
from forms import LoginForm, SignUpForm, AdminLoginForm, AdminSignUpForm, AddPatientForm, PatientLoginForm, \
    UpdatePatientPasswordForm
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
from deepStega import test
from torchvision import transforms
from email.message import EmailMessage
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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
    return Users.query.get(int(user_id)) or Admin.query.get(int(user_id)) or Patients.query.get(int(user_id))


def login_required(role="ANY"):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            # urole = current_app.login_manager.reload_user().get_urole()
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


class Users(mydb.Model, UserMixin):
    id = mydb.Column(mydb.Integer, primary_key=True)
    name = mydb.Column(mydb.String(20), nullable=False)
    employeeID = mydb.Column(mydb.String(10), unique=True, nullable=False)
    email = mydb.Column(mydb.String(50), unique=True, nullable=False)
    phone = mydb.Column(mydb.String(11), nullable=False)
    department = mydb.Column(mydb.String(20), nullable=False)
    occupation = mydb.Column(mydb.String(20), nullable=False)
    salt = mydb.Column(mydb.String(256), nullable=False)
    password = mydb.Column(mydb.String(256), nullable=False)
    changePwd = mydb.Column(mydb.Boolean, default=False)
    urole = mydb.Column(mydb.String(80), default="Employee")

    encryption_details = mydb.relationship('Encryption', back_populates='physician_details')

    def __init__(self, name, employeeID, email, phone, department, occupation, salt, password, changePwd, urole):
        self.name = name
        self.employeeID = employeeID
        self.email = email
        self.phone = phone
        self.department = department
        self.occupation = occupation
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
        return f"User('{self.id}','{self.name}','{self.employeeID}','{self.email}','{self.phone}','{self.department}','{self.occupation}','{self.password}')"


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
    cover_image = mydb.Column(mydb.Text, nullable=True, default='Null')
    patient_id = mydb.Column(mydb.String(45), mydb.ForeignKey('patients.patientID'), nullable=False)
    patient_name = mydb.Column(mydb.String(50), nullable=False)
    department = mydb.Column(mydb.String(20), nullable=False)
    image_title = mydb.Column(mydb.String(100), nullable=False)
    image_category = mydb.Column(mydb.String(50), nullable=False)
    date_of_creation = mydb.Column(mydb.DateTime, nullable=False)
    rsa_public = mydb.Column(mydb.String(500), nullable=False)
    aes_encrypted_key = mydb.Column(mydb.BLOB, nullable=False)
    iv = mydb.Column(mydb.BLOB, nullable=False)
    physician_name = mydb.Column(mydb.String(50), nullable=False)
    physician_id = mydb.Column(mydb.String(10), mydb.ForeignKey('users.employeeID'), nullable=False)
    creator_email = mydb.Column(mydb.String(50), nullable=False)

    physician_details = mydb.relationship('Users', back_populates="encryption_details")
    patient_details = mydb.relationship('Patients', back_populates="medical_history")
    key_details = mydb.relationship('Key', back_populates="crypto_details")

    # create a string
    def __repr__(self):
        return f"Conversion('{self.image_id}','{self.encrypted_medical_image}','{self.patient_name}','{self.department}','{self.image_title}','{self.image_category}'," \
               f"'{self.date_of_creation}','{self.rsa_public}','{self.aes_encrypted_key}','{self.iv}','{self.physician_name}','{self.physician_id}')"


class Key(mydb.Model):
    key_id = mydb.Column(mydb.Integer, primary_key=True)
    rsa_private = mydb.Column(mydb.String(500), nullable=False)
    image_id = mydb.Column(mydb.Integer, mydb.ForeignKey('encryption.image_id'), nullable=False)

    crypto_details = mydb.relationship('Encryption', back_populates="key_details")

    # create a string
    def __repr__(self):
        return f"Key('{self.key_id}','{self.rsa_private}','{self.image_id}')"


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
                    hashed_password = hashlib.pbkdf2_hmac('sha256', user_pwd, salt, 10000)
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
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        # check whether the user is existed
        user = Users.query.filter_by(employeeID=form.employeeID.data).first()
        # if the user is existed
        if user:
            # get the password and hash the password with salt
            user_pwd = form.password.data.encode()
            get_user_hash = hashlib.pbkdf2_hmac('sha256', user_pwd, bytes.fromhex(user.salt), 10000)
            hex_hash = get_user_hash.hex()

            # compare the hashed password with the particular user password that stored in db
            if hex_hash == user.password:
                login_user(user, remember=False, duration=None, force=False, fresh=True)
                return redirect(url_for('home'))
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
                return render_template('signUp.html', title='signUp', form=form)

            # if it is matched
            else:
                # check whether the employee ID had been set up
                user = Users.query.filter_by(employeeID=form.employeeID.data).first()
                # if the employee ID is not being used
                if user is None:
                    # generate a random salt for password
                    salt = os.urandom(32)
                    # get user input for password
                    user_pwd = form.confirmed_password.data.encode()
                    # hash the password with salt
                    hashed_password = hashlib.pbkdf2_hmac('sha256', user_pwd, salt, 10000)
                    # convert the hashed password to hex
                    hex_hash = hashed_password.hex()
                    # convert the salt to hex
                    hex_salt = salt.hex()

                    # add user details into db
                    user = Users(name=form.name.data, employeeID=form.employeeID.data, email=form.email.data,
                                 phone=form.mobileNumber.data, department=form.department.data,
                                 occupation=form.occupation.data, salt=hex_salt, password=hex_hash, changePwd=False,
                                 urole="Employee")
                    mydb.session.add(user)
                    mydb.session.commit()

                    flash(f'Account created for {form.employeeID.data}', 'success')
                    form.name.data = ""
                    form.employeeID.data = ""
                    form.email.data = ""
                    form.mobileNumber.data = ""
                    form.department.data = ""
                    form.occupation.data = ""
                    return render_template('signUp.html', title='signUp', form=form)

                # if the employee ID had been used
                if user:
                    flash(f'This employee ID is taken!', 'danger')
                    return render_template('signUp.html', title='signUp', form=form)

    return render_template('signUp.html', title='signUp', form=form)


@app.route("/addPatient", methods=['GET', 'POST'], endpoint='addPatient')
@login_required(role="Employee")
def addPatient():
    form = AddPatientForm()

    if form.validate_on_submit():
        # check whether the patient ID had been set up
        patient = Patients.query.filter_by(patientID=form.patientID.data).first()
        # if the employee ID is not being used
        if patient is None:
            # generate a random salt for password
            salt = os.urandom(32)
            # get user input for password
            patient_pwd = form.ic.data.encode()
            # hash the password with salt
            hashed_password = hashlib.pbkdf2_hmac('sha256', patient_pwd, salt, 10000)
            # convert the hashed password to hex
            hex_hash = hashed_password.hex()
            # convert the salt to hex
            hex_salt = salt.hex()

            # add patient details into db
            patient = Patients(name=form.name.data, patientID=form.patientID.data, email=form.email.data,
                               phone=form.mobileNumber.data, ic=form.ic.data,
                               born_date=form.born_date.data, gender=form.gender.data, salt=hex_salt, password=hex_hash,
                               changePwd=False, urole="Patient")
            mydb.session.add(patient)
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
    # if current_user.is_authenticated:
    #     return redirect(url_for('home'))
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
        medical_records = mydb.session.query(Users, Encryption).join(Users).filter(
            Encryption.patient_id == current_user.patientID).order_by(Encryption.image_id).all()
    return render_template('medicalRecords.html', title='medicalRecords', patient_records=patient_records,
                           medical_records=medical_records)


@app.route('/physician_name/<get_physician_employeeID>')
def physician(get_physician_employeeID):
    physician_name = Users.query.filter_by(employeeID=get_physician_employeeID).all()
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
        form.physician_id.choices = ['Please select a physician'] + [g.employeeID for g in Users.query.filter(
            Users.name == current_user.name).all()]
    elif current_user.occupation == 'Nurse':
        form.physician_id.choices = ['Please select a physician'] + [g.employeeID for g in
                                                                     Users.query.filter(Users.isAdmin == False).filter(
                                                                         Users.occupation == 'Doctor').filter(
                                                                         Users.department == current_user.department).all()]

    if request.method == 'POST':
        print(form.physician_id.data)
        result = Users.query.filter_by(employeeID=form.physician_id.data).first()
        form.physician_name.data = result.name
        form.department.data = result.department
        patientData = Patients.query.filter_by(patientID=form.patient_id.data).first()
        form.name.data = patientData.name
        print(form.name.data)
        print(form.physician_name.data)

    if form.validate_on_submit():
        if 'medical_image_file' in request.files:
            photo = request.files['medical_image_file']
            if photo.filename != '':
                # get user uploaded image data and encrypt it
                image = request.files['medical_image_file']
                # compressed_image = base64.b64encode(compressor.image_compressor(image))
                #
                # key = secrets.token_bytes(24)
                # iv = secrets.token_bytes(16)
                #
                # cipher = AES.new(key, AES.MODE_CBC, iv)
                #
                # start_time = time.time()
                # msg = cipher.encrypt(pad(compressed_image, 16))
                # msg3 = base64.b64encode(msg)
                # # print(msg3)
                # print("--- %s seconds ---" % (time.time() - start_time))
                #
                # decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
                # msg1 = unpad(decrypt_cipher.decrypt(msg), 16)
                # msg2 = codecs.decode(msg1, 'utf-8')
                # print(msg2)

                # image_string = image.read()
                # print(image_string)
                # compressed = cv2.imread(image_string)
                compressed_image = base64.b64encode(compressor.image_compressor(image))

                # create random 24 bytes key and 16 bytes iv
                key = secrets.token_bytes(24)
                iv = secrets.token_bytes(16)
                cipher = aes.AES(key=key, iv=iv)
                start_time = time.time()

                msg = cipher.encrypt(compressed_image)
                msg1 = base64.b64encode(msg)
                print("--- %s seconds ---" % (time.time() - start_time))

                # enc_image = np.frombuffer(msg1, np.uint8).reshape(compressed.shape)
                # save_path = asksaveasfilename()
                # enc_image.save(save_path + ".png")

                # encrypt AES secret key
                # publicKey, privateKey = RSA.newkeys(512)
                # print(privateKey)
                # encryptedKey = RSA.encrypt(key, publicKey)
                # print(encryptedKey)

                random_generator = Random.new().read
                keyPair = RSA.generate(2048, random_generator)
                privateKey, publicKey = keyPair, keyPair.public_key()

                rsa_cipher = PKCS1_OAEP.new(publicKey)
                encryptedKey = rsa_cipher.encrypt(key)

                # add user details into db
                image = Encryption(encrypted_medical_image=msg, patient_name=form.name.data,
                                   patient_id=form.patient_id.data,
                                   department=form.department.data,
                                   image_title=form.title.data, image_category=form.category.data,
                                   date_of_creation=form.date.data, rsa_public=publicKey,
                                   aes_encrypted_key=encryptedKey, iv=iv,
                                   physician_name=form.physician_name.data, physician_id=form.physician_id.data,
                                   creator_email=current_user.email)
                mydb.session.add(image)
                mydb.session.commit()
                mydb.session.flush()
                print(image.image_id)

                folder_name = image.department
                print(folder_name)
                folder = os.path.join("C:/Users/User/Documents/FYP_Program", folder_name)
                print(folder)
                if not os.path.exists(folder):
                    os.makedirs(folder)
                new_file = f'{image.image_id}.pem'

                f = open(os.path.join(folder, new_file), 'wb')
                f.write(privateKey.exportKey('PEM'))
                f.close()

                key = Key(rsa_private=privateKey, image_id=image.image_id)
                mydb.session.add(key)
                mydb.session.commit()

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

                return render_template('home.html', filestring=compressed_image, form=form)

    return render_template('home.html', title='home', form=form)


@app.route("/review", methods=['GET', 'POST'], endpoint='review')
@login_required(role="Employee")
def review():
    if current_user.is_authenticated:
        if current_user.occupation == 'Nurse':
            image_data = mydb.session.query(Users, Encryption).join(Users).filter(
                Encryption.department == current_user.department).order_by(Encryption.image_id).all()
        elif current_user.occupation == 'Doctor':
            image_data = mydb.session.query(Users, Encryption).join(Users).filter(
                Encryption.physician_name == current_user.name).order_by(Encryption.image_id).all()
    return render_template('review.html', title='review', images=image_data)


@app.route("/decrypt", methods=['GET', 'POST'], endpoint='decrypt')
@login_required(role="Employee")
def decrypt():
    form = ConversionForm()

    if request.method == 'POST':
        image_data = request.form.get('image_id')
        print(image_data)
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
        decrypt_cipher = aes.AES(key=decrypted_key, iv=key_data.iv)
        start_time = time.time()

        decrypt_msg = decrypt_cipher.decrypt(key_data.encrypted_medical_image)
        decrypt_msg1 = codecs.decode(decrypt_msg, 'UTF-8')
        decrypt_msg2 = aes.AES.delete_padding(decrypt_msg1)
        testt = base64.b64decode(decrypt_msg2)
        print(testt)
        decrypted_img = Image.open(io.BytesIO(testt))
        save_path = asksaveasfilename()
        decrypted_img.save(save_path + ".png")

        print(decrypt_msg2)
        print("--- %s seconds ---" % (time.time() - start_time))
    return render_template('review.html', title='review', form=form)


@app.route("/reviewStaff", methods=['GET', 'POST'], endpoint='staffDB')
@login_required(role="Admin")
def staffDB():
    if current_user.is_authenticated:
        staff_data = Users.query.all()
    return render_template('staffDB.html', title='staffDB', staffs=staff_data)


@app.route('/patientInfo/<patient_id>', methods=['GET', 'POST'], endpoint='patientInfo')
@login_required(role="Employee")
def patientInfo(patient_id):
    form = ConversionForm()

    patient_data = Patients.query.filter(Patients.patientID == patient_id).all()
    patient_record = mydb.session.query(Users, Encryption).join(Users).filter(
        Encryption.patient_id == patient_id).order_by(Encryption.image_id).all()
    return render_template('patientInfo.html', title='patientInfo', patient_data=patient_data,
                           patient_record=patient_record, form=form)


def init_weights(m):
    warnings.filterwarnings('ignore')
    classname = m.__class__.__name__
    if classname.find('Conv') != -1:
        init.kaiming_normal(m.weight.data, a=0, mode='fan_in')
    elif classname.find('BatchNorm') != -1:
        m.weight.data.normal_(1.0, 0.02)
        m.bias.data.fill_(0)


def input_transform(crop_size):
    return transforms.Compose([
        transforms.Resize(crop_size),
        transforms.ToTensor(),
    ])


@app.route("/deepSteganography", methods=['GET', 'POST'], endpoint='deepSteganography')
def deepSteganography():
    form = ConversionForm()

    if request.method == 'POST':
        cover_file = request.files["cover_image"]
        cover_img = Image.open(cover_file)
        cover_img_resize = cover_img.resize((256, 256))
        cover_save_path = r'C:/Users/User/Documents/FYP_Program/data/2'
        cover_img_resize.save(cover_save_path + ".png")

        secret_data = request.form.get('image_id')
        key_data = mydb.session.query(Encryption).filter(Encryption.image_id == secret_data).first()

        # get the keyfile directory
        folder_name = key_data.department
        folder = os.path.join('C:/Users/User/Documents/FYP_Program', folder_name)
        filename = f'{key_data.image_id}.pem'

        # decrypt process
        f = open(os.path.join(folder, filename), 'rb')
        privateKey = RSA.importKey(f.read())
        rsa_decrypt_cipher = PKCS1_OAEP.new(privateKey)
        decrypted_key = rsa_decrypt_cipher.decrypt(key_data.aes_encrypted_key)
        decrypt_cipher = aes.AES(key=decrypted_key, iv=key_data.iv)

        decrypt_msg = decrypt_cipher.decrypt(key_data.encrypted_medical_image)
        decrypt_msg1 = codecs.decode(decrypt_msg, 'UTF-8')
        decrypt_msg2 = aes.AES.delete_padding(decrypt_msg1)
        secret_decode = base64.b64decode(decrypt_msg2)
        decrypted_img = Image.open(io.BytesIO(secret_decode))
        decrypted_img_resize = decrypted_img.resize((256, 256))
        secret_save_path = r'C:/Users/User/Documents/FYP_Program/data/1'
        decrypted_img_resize.save(secret_save_path + ".png")
        start_time = time.time()

        test()

        sendDetails = Encryption.query.filter(Encryption.image_id == secret_data).first()
        getEmail = mydb.session.query(Patients, Encryption).join(Patients).filter(Encryption.patient_id == request.form.get('patient_id')).first()
        print(getEmail.email)

        msg = EmailMessage()
        msg['From'] = "jxuan0811@gmail.com"
        msg['To'] = getEmail.email
        msg['Subject'] = 'Request Medical Image'
        password = "Ap411738Cd./"

        patientName = sendDetails.patient_name
        patientID = sendDetails.patient_id
        department = sendDetails.department
        imageTitle = sendDetails.image_title
        imageCategory = sendDetails.image_category
        dateOfCreation = sendDetails.date_of_creation
        physicianName = sendDetails.physician_name
        physicianID = sendDetails.physician_id

        msg.set_content("Request Details: \n" \
                        "Patient Name: {0}\n" \
                        "Patient ID: {1}\n" \
                        "Department = {2}\n" \
                        "Image Title = {3}\n" \
                        "Image Category = {4}\n" \
                        "Date of Creation = {5}\n" \
                        "Physician Name = {6}\n" \
                        "Physician ID = {7}\n".format(patientName, patientID, department, imageTitle, imageCategory,
                                                      dateOfCreation, physicianName, physicianID))

        filename = open(r'C:/Users/User/Documents/FYP_Program/sendImage/outputImage.png')
        msgImage = MIMEImage(filename.read())
        filename.close()

        msgImage.add_header('Medical Image', '<image1>')
        msg.attach(msgImage)

        port = 465
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
            server.login('jxuan0811@gmail.com', password)
            print("Login successfully")
            server.send_message(msg)
            print("Email sent!")

        print("--- %s seconds ---" % (time.time() - start_time))
    return render_template('review.html', title='review', form=form)


@app.route('/request/<image_id>', methods=['GET', 'POST'], endpoint='requestImage')
@login_required(role="Patient")
def requestImage(image_id):
    requestDetails = Encryption.query.filter(Encryption.image_id == image_id).first()

    msg = EmailMessage()
    msg['From'] = "jxuan0811@gmail.com"
    msg['To'] = requestDetails.creator_email
    msg['Subject'] = 'Request Medical Image'
    password = "Ap411738Cd./"

    patientName = requestDetails.patient_name
    patientID = requestDetails.patient_id
    department = requestDetails.department
    imageTitle = requestDetails.image_title
    imageCategory = requestDetails.image_category
    dateOfCreation = requestDetails.date_of_creation
    physicianName = requestDetails.physician_name
    physicianID = requestDetails.physician_id

    msg.set_content("Request Details: \n" \
                    "Patient Name: {0}\n" \
                    "Patient ID: {1}\n" \
                    "Department = {2}\n" \
                    "Image Title = {3}\n" \
                    "Image Category = {4}\n" \
                    "Date of Creation = {5}\n" \
                    "Physician Name = {6}\n" \
                    "Physician ID = {7}\n".format(patientName, patientID, department, imageTitle, imageCategory,
                                                  dateOfCreation, physicianName, physicianID))

    port = 465
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
        server.login('jxuan0811@gmail.com', password)
        print("Login successfully")
        server.send_message(msg)
        print("Email sent!")

    return render_template('medicalRecords.html', title='medicalRecords')


@app.route("/logout", endpoint='logout')
def logout():
    logout_user()
    return redirect(url_for('login_selection'))


if __name__ == '__main__':
    app.run(debug=True)
