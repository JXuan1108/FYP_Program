from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField, DateField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_wtf.file import FileField, FileAllowed, FileRequired


class SignUpForm(FlaskForm):
    name = StringField('Name',
                       validators=[DataRequired(), Length(min=2, max=20, message='Name must be at least 2 characters')])
    employeeID = StringField('Employee ID', validators=[DataRequired(), Length(min=10, max=10)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    mobileNumber = StringField('Mobile Number', validators=[DataRequired(), Length(min=10, max=11,
                                                                                   message='Name must be between 10-11 numbers')])
    department = StringField('Department',
                             validators=[DataRequired(),
                                         Length(min=10, max=50, message='Name must be at least 10 characters')])
    occupation = SelectField('Occupation', choices=[('Doctor', 'Doctor'), ('Nurse', 'Nurse')])
    ic = StringField('ID Number/ Passport Number', validators=[DataRequired(), Length(min=8)])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female')])
    submit = SubmitField('Add New User')


class LoginForm(FlaskForm):
    employeeID = StringField('Employee ID', validators=[DataRequired(),
                                                        Length(min=10, max=10)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class AdminSignUpForm(FlaskForm):
    name = StringField('Name',
                       validators=[DataRequired(), Length(min=2, max=20, message='Name must be at least 2 characters')])
    adminID = StringField('Admin ID', validators=[DataRequired(), Length(min=10, max=10)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirmed_password = PasswordField('Confirmed Password',
                                       validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Sign Up')


class AdminLoginForm(FlaskForm):
    adminID = StringField('Admin ID', validators=[DataRequired(), Length(min=10, max=10)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class AddPatientForm(FlaskForm):
    name = StringField('Patient Name',
                       validators=[DataRequired(), Length(min=2, max=20, message='Name must be at least 2 characters')])
    patientID = StringField('Patient ID', validators=[DataRequired(), Length(min=10, max=10)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    mobileNumber = StringField('Mobile Number', validators=[DataRequired(), Length(min=10, max=11,
                                                                                   message='Name must be between 10-11 numbers')])
    ic = StringField('ID Number/ Passport Number', validators=[DataRequired(), Length(min=12, max=15,
                                                                                   message='Name must be at least 12 numbers')])
    born_date = DateField('Born Date', format='%Y-%m-%d')
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female')])
    submit = SubmitField('Add Patient')


class PatientLoginForm(FlaskForm):
    patientID = StringField('Patient ID', validators=[DataRequired(), Length(min=10, max=10)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class UpdatePatientPasswordForm(FlaskForm):
    patientID = StringField('Patient ID', validators=[DataRequired(), Length(min=10, max=10)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirmedPassword = PasswordField('Confirmed Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class UpdateUserPasswordForm(FlaskForm):
    employeeID = StringField('Employee ID', validators=[DataRequired(), Length(min=10, max=10)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirmedPassword = PasswordField('Confirmed Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RevealImageForm(FlaskForm):
    reveal_image_file = FileField('Medical Image to Reveal', validators=[FileRequired(), FileAllowed(['png', 'jpg', 'jpeg'],
                                                                                            message='We only accept JPG, JPEG or PNG file')])
    submit = SubmitField('Reveal')