from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)

# Configure the database URI and secret key for sessions
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Path to your SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # To disable the modification tracking
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Set a secret key for sessions (change it)

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Define the User model for authentication (login, register)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"User('{self.full_name}', '{self.email}')"

# Define the Profile model for profile-related details (dob, gender, etc.)
class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    dob = db.Column(db.String(20), nullable=True)
    gender = db.Column(db.String(10), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    state = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)

    user = db.relationship('User', backref=db.backref('profile', uselist=False))

    def __repr__(self):
        return f"Profile('{self.user_id}')"

# Routes
@app.route("/")
def home():
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(full_name=full_name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            return redirect(url_for('user_profile', user_id=user.id))
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        flash('Password reset instructions have been sent to your email', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/user_profile/<int:user_id>', methods=['GET', 'POST'])
def user_profile(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('home'))

    # Check if profile exists
    profile = Profile.query.filter_by(user_id=user_id).first()

    if request.method == 'POST':
        dob = request.form.get('dob')
        gender = request.form.get('gender')
        country = request.form.get('country')
        state = request.form.get('state')
        city = request.form.get('city')

        if not dob or not gender or not country or not state or not city:
            flash('Please fill all the required fields.', 'danger')
            return render_template('user_profile.html', user=user, profile=profile)

        # Update or create profile
        if profile:
            profile.dob = dob
            profile.gender = gender
            profile.country = country
            profile.state = state
            profile.city = city
        else:
            new_profile = Profile(
                user_id=user.id,
                dob=dob,
                gender=gender,
                country=country,
                state=state,
                city=city,
            )
            db.session.add(new_profile)

        db.session.commit()

        flash('Profile updated successfully', 'success')
        return redirect(url_for('user_interests'))  # Redirect to the next page

    return render_template('user_profile.html', user=user, profile=profile)

@app.route('/user_profile/user_interests.html')
def user_interests():
    return render_template('user_interests.html')

@app.route('/user_profile/career.html')
def career_page():
    return render_template('career.html')

@app.route('/user_profile/career11.html')
def career11():
    return render_template('career11.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create all tables in the database
    app.run(debug=True)



