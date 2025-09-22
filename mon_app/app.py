# Logique principale de l'application Flask

from flask import Flask, render_template, request, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

app = Flask(__name__)
app.config['SECRET_KEY'] = 'votre-clé-secrète'

class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Logique de connexion ici
        flash('Connexion réussie!', 'success')
    return render_template('login.html', form=form)
@app.route('/password')
def password():
    return render_template('password.html')

if __name__ == '__main__':
    app.run(debug=True)
