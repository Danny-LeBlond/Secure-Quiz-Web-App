
import os
from dotenv import load_dotenv
load_dotenv()
import random
import logging
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from functools import wraps
from flask_wtf import CSRFProtect
from flask import (
    Flask, render_template, render_template_string, redirect, url_for,
    request, flash, session, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
def create_app():
    app = Flask(__name__)
    csrf = CSRFProtect(app)
    @app.route('/delete_account', methods=['POST'])
    @login_required
    def delete_account():
        user = current_user
        AttemptAnswer.query.filter(
            AttemptAnswer.attempt_id.in_(
                [a.id for a in QuizAttempt.query.filter_by(user_id=user.id)]
            )
        ).delete(synchronize_session=False)
        QuizAttempt.query.filter_by(user_id=user.id).delete()
        Score.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
        logging.info(f"Account deleted: {user.username}")
        logout_user()
        flash('Your account and all associated data have been deleted.', 'info')
        return redirect(url_for('welcome'))
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'super-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'quiz.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    logging.basicConfig(
        filename='app.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    log = logging.getLogger('werkzeug')
    log.disabled = True
    def send_admin_otp_email(recipient_email, otp_code):
        sender_email = os.environ.get("EMAIL_USER")
        sender_pass = os.environ.get("EMAIL_PASS")
        if not sender_email or not sender_pass:
            print("Missing email credentials.")
            return
        if not recipient_email:
            print("Missing recipient email address.")
            return
        message = MIMEText(f"Your Admin OTP code is: {otp_code}")
        message['Subject'] = "Your Admin Login OTP"
        message['From'] = sender_email
        message['To'] = recipient_email
        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(sender_email, sender_pass)
                server.send_message(message)
            print(f"OTP Email sent to {recipient_email}")
        except Exception as e:
            print(f" Failed to send OTP email: {e}")
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('500.html'), 500
    def admin_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != 'admin':
                abort(403)
            return f(*args, **kwargs)
        return decorated
    @app.route('/')
    def welcome():
        if current_user.is_authenticated and current_user.role == 'admin':
            logout_user()
        return render_template('welcome.html')
    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('index.html')
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            import re
            if (len(password) < 8 or 
                not re.search(r"[A-Z]", password) or 
                not re.search(r"[a-z]", password) or 
                not re.search(r"[0-9]", password)):
                flash('Password must be at least 8 characters long, include at least one uppercase letter, one lowercase letter, and one number.', 'danger')
                logging.info(f"Failed registration attempt with username: {username}")
                return redirect(url_for('register'))
            if not username or not password:
                flash('Username and password required', 'danger')
                logging.info(f"Failed registration attempt with username: {username}")
                return redirect(url_for('register'))
            if User.query.filter_by(username=username).first():
                flash('Username already taken', 'danger')
                logging.info(f"Failed registration attempt with username: {username}")
                return redirect(url_for('register'))
            user = User(username=username, role='player')
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            logging.info(f"User registered successfully: {username}")
            flash('Registered successfully. Please log in.', 'success')
            return redirect(url_for('login'))
        return render_template('register.html')
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                if user.role == 'admin':
                    otp = ''.join(random.choices('0123456789', k=6))
                    session['pending_admin_id'] = user.id
                    session['admin_otp'] = otp
                    email_to = os.environ.get("EMAIL_TO")
                    send_admin_otp_email(email_to, otp)
                    flash('Admin detected. OTP sent to admin email.', 'info')
                    return redirect(url_for('verify_admin_otp'))
                else:
                    login_user(user)
                    logging.info(f"Login: {username}")
                    return redirect(url_for('dashboard'))
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))
        return render_template('login.html')
    @app.route('/verify_admin_otp', methods=['GET', 'POST'])
    def verify_admin_otp():
        if 'pending_admin_id' not in session:
            flash('Session expired. Please login again.', 'danger')
            return redirect(url_for('login'))
        if request.method == 'POST':
            entered_otp = request.form.get('otp')
            if entered_otp == session.get('admin_otp'):
                user = User.query.get(session['pending_admin_id'])
                if user:
                    login_user(user)
                    logging.info(f"Admin login: {user.username}")
                    flash('Admin login successful.', 'success')
                    session.pop('pending_admin_id', None)
                    session.pop('admin_otp', None)
                    return redirect(url_for('dashboard'))
                else:
                    flash('User not found.', 'danger')
                    return redirect(url_for('login'))
            else:
                flash('Invalid OTP. Please try again.', 'danger')
        return render_template('verify_admin_otp.html')
    @app.route('/logout')
    @login_required
    def logout():
        logging.info(f'Logout: {current_user.username}')
        logout_user()
        return redirect(url_for('login'))
    @app.route('/quiz', methods=['GET', 'POST'])
    @login_required
    def quiz():
        if 'qids' not in session:
            all_ids = [q.id for q in Question.query.all()]
            random.shuffle(all_ids)
            session['qids'] = all_ids[:10]
            session['current'] = 0
            session['score'] = 0
            session['responses'] = []
        if request.method == 'POST':
            choice = request.form.get('choice')
            idx = session['current']
            qid = session['qids'][idx]
            q = Question.query.get(qid)
            if q is None:
                logging.warning(f"Question with ID {qid} not found. Ending quiz early.")
                return redirect(url_for('results'))
            correct = (choice == q.correct_choice)
            session['score'] += 1 if correct else 0
            session['responses'].append({
                'qid': qid,
                'choice': choice,
                'correct': correct
            })
            session['current'] += 1
            if session['current'] >= len(session['qids']):
                if session['score'] == len(session['qids']):
                    remaining = list(set([q.id for q in Question.query.all()]) - set(session['qids']))
                    if remaining:
                        session['qids'].append(random.choice(remaining))
                    else:
                        return redirect(url_for('results'))
                else:
                    return redirect(url_for('results'))
        idx = session['current']
        if not session['qids'] or idx >= len(session['qids']):
            return redirect(url_for('results'))
        qid = session['qids'][idx]
        question = Question.query.get(qid)
        return render_template('quiz.html', question=question, num=idx+1)
    @app.route('/results')
    @login_required
    def results():
        final_score = session.get('score', 0)
        responses = session.get('responses', [])
        attempt = QuizAttempt(user_id=current_user.id, score=final_score)
        db.session.add(attempt)
        db.session.commit()
        for r in responses:
            ans = AttemptAnswer(
                attempt_id=attempt.id,
                question_id=r['qid'],
                chosen_choice=r['choice'],
                is_correct=r['correct']
            )
            db.session.add(ans)
        entry = Score(user_id=current_user.id, score=final_score)
        db.session.add(entry)
        db.session.commit()
        logging.info(f"Quiz completed by {current_user.username} with score {final_score}")
        enriched = []
        for r in responses:
            q = Question.query.get(r['qid'])
            enriched.append({
                'text': q.text,
                'choice': r['choice'],
                'correct_choice': q.correct_choice
            })
        for k in ('qids', 'current', 'score', 'responses'):
            session.pop(k, None)
        return render_template('results.html', score=final_score, responses=enriched, total=len(enriched))
    @app.route('/leaderboard')
    @login_required
    def leaderboard():
        top = Score.query.order_by(Score.score.desc(), Score.timestamp).limit(10).all()
        return render_template('leaderboard.html', scores=top)
    @app.route('/admin/scores')
    @login_required
    @admin_required
    def admin_scores():
        scores = Score.query.order_by(Score.timestamp.desc()).all()
        return render_template('admin_scores.html', scores=scores)
    @app.route('/admin/score/<int:id>/edit', methods=['GET','POST'])
    @login_required
    @admin_required
    def edit_score(id):
        score = Score.query.get_or_404(id)
        if request.method == 'POST':
            try:
                new = int(request.form.get('score'))
                score.score = new
                db.session.commit()
                logging.info(f"Admin {current_user.username} edited score ID {id} to {new}")
                return redirect(url_for('admin_scores'))
            except ValueError:
                flash('Invalid score', 'danger')
        return render_template('edit_score.html', score=score)
    @app.route('/admin/score/<int:id>/delete', methods=['POST'])
    @login_required
    @admin_required
    def delete_score(id):
        score = Score.query.get_or_404(id)
        db.session.delete(score)
        db.session.commit()
        logging.info(f"Admin {current_user.username} deleted score ID {id}")
        return redirect(url_for('admin_scores'))
    @app.route('/admin/attempts')
    @login_required
    @admin_required
    def admin_attempts():
        attempts = QuizAttempt.query.order_by(QuizAttempt.timestamp.desc()).all()
        return render_template('admin_attempts.html', attempts=attempts)
    @app.route('/admin/attempt/<int:id>')
    @login_required
    @admin_required
    def view_attempt(id):
        attempt = QuizAttempt.query.get_or_404(id)
        enriched_responses = []
        for r in attempt.responses:
            question = Question.query.get(r.question_id)
            enriched_responses.append({
                'question': question,
                'chosen_choice': r.chosen_choice,
                'is_correct': r.is_correct
            })
        return render_template('view_attempt.html', attempt=attempt, responses=enriched_responses)
    return app
db = SQLAlchemy()
login_manager = LoginManager()
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='player', nullable=False)
    scores = db.relationship('Score', backref='user', lazy=True)
    attempts = db.relationship('QuizAttempt', backref='user', lazy=True)
    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)
    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    choice_a = db.Column(db.String(200), nullable=False)
    choice_b = db.Column(db.String(200), nullable=False)
    choice_c = db.Column(db.String(200), nullable=False)
    choice_d = db.Column(db.String(200), nullable=False)
    correct_choice = db.Column(db.String(1), nullable=False)
class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    responses = db.relationship('AttemptAnswer', backref='attempt', lazy=True)
class AttemptAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attempt_id = db.Column(db.Integer, db.ForeignKey('quiz_attempt.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    chosen_choice = db.Column(db.String(1), nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)
class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
def seed_questions():
    Question.query.delete()
    db.session.commit()
    questions = []
    questions.append(Question(text="What is 1 + 1?", choice_a="2", choice_b="4", choice_c="window", choice_d="9", correct_choice="A"))
    questions.append(Question(text="What color is the sky on a clear day?", choice_a="Green", choice_b="Red", choice_c="Blue", choice_d="Yellow", correct_choice="C"))
    questions.append(Question(text="Which animal barks?", choice_a="Cat", choice_b="Dog", choice_c="Bird", choice_d="Fish", correct_choice="B"))
    questions.append(Question(text="What is the capital of France?", choice_a="Berlin", choice_b="Paris", choice_c="London", choice_d="Madrid", correct_choice="B"))
    questions.append(Question(text="Which planet is known as the Red Planet?", choice_a="Earth", choice_b="Venus", choice_c="Mars", choice_d="Jupiter", correct_choice="C"))
    questions.append(Question(text="What gas do plants absorb?", choice_a="Oxygen", choice_b="Nitrogen", choice_c="Hydrogen", choice_d="Carbon Dioxide", correct_choice="D"))
    questions.append(Question(text="How many continents are there?", choice_a="5", choice_b="6", choice_c="7", choice_d="8", correct_choice="C"))
    questions.append(Question(text="What is H2O commonly known as?", choice_a="Salt", choice_b="Water", choice_c="Sugar", choice_d="Oxygen", correct_choice="B"))
    questions.append(Question(text="What does a thermometer measure?", choice_a="Length", choice_b="Weight", choice_c="Temperature", choice_d="Speed", correct_choice="C"))
    questions.append(Question(text="What does DNA stand for?", choice_a="Deoxyribonucleic Acid", choice_b="Digital Network Access", choice_c="Data Number Array", choice_d="None of the above", correct_choice="A"))
    questions.append(Question(text="Which month has 28 days?", choice_a="February", choice_b="All of them", choice_c="June", choice_d="April", correct_choice="B"))
    questions.append(Question(text="Which ocean is the largest?", choice_a="Atlantic", choice_b="Arctic", choice_c="Indian", choice_d="Pacific", correct_choice="D"))
    questions.append(Question(text="What year did World War II end?", choice_a="1940", choice_b="1945", choice_c="1950", choice_d="1939", correct_choice="B"))
    questions.append(Question(text="What is the main ingredient in bread?", choice_a="Salt", choice_b="Flour", choice_c="Sugar", choice_d="Butter", correct_choice="B"))
    questions.append(Question(text="What fruit keeps the doctor away?", choice_a="Banana", choice_b="Apple", choice_c="Pear", choice_d="Grapes", correct_choice="B"))
    questions.append(Question(text="What is the boiling point of water in Celsius?", choice_a="100", choice_b="0", choice_c="212", choice_d="50", correct_choice="A"))
    questions.append(Question(text="What is the freezing point of water?", choice_a="0°C", choice_b="100°C", choice_c="32°C", choice_d="10°C", correct_choice="A"))
    questions.append(Question(text="What is the square root of 64?", choice_a="6", choice_b="7", choice_c="8", choice_d="9", correct_choice="C"))
    questions.append(Question(text="Which animal is known as the King of the Jungle?", choice_a="Tiger", choice_b="Elephant", choice_c="Lion", choice_d="Bear", correct_choice="C"))
    questions.append(Question(text="Which language has the most native speakers?", choice_a="English", choice_b="Mandarin", choice_c="Spanish", choice_d="Hindi", correct_choice="B"))
    questions.append(Question(text="What is the tallest mountain in the world?", choice_a="K2", choice_b="Everest", choice_c="Kilimanjaro", choice_d="Denali", correct_choice="B"))
    questions.append(Question(text="Who painted the Mona Lisa?", choice_a="Van Gogh", choice_b="Michelangelo", choice_c="Da Vinci", choice_d="Picasso", correct_choice="C"))
    questions.append(Question(text="What is the hardest natural substance on Earth?", choice_a="Iron", choice_b="Diamond", choice_c="Quartz", choice_d="Gold", correct_choice="B"))
    questions.append(Question(text="How many legs does a spider have?", choice_a="6", choice_b="8", choice_c="10", choice_d="12", correct_choice="B"))
    questions.append(Question(text="What is the currency of Japan?", choice_a="Yen", choice_b="Won", choice_c="Dollar", choice_d="Euro", correct_choice="A"))
    questions.append(Question(text="Which element is needed for breathing?", choice_a="Carbon", choice_b="Oxygen", choice_c="Hydrogen", choice_d="Nitrogen", correct_choice="B"))
    questions.append(Question(text="How many planets are in the Solar System?", choice_a="8", choice_b="9", choice_c="7", choice_d="10", correct_choice="A"))
    questions.append(Question(text="What is the capital city of Italy?", choice_a="Venice", choice_b="Rome", choice_c="Milan", choice_d="Naples", correct_choice="B"))
    questions.append(Question(text="What is the fastest land animal?", choice_a="Cheetah", choice_b="Lion", choice_c="Horse", choice_d="Greyhound", correct_choice="A"))
    questions.append(Question(text="How many degrees are in a circle?", choice_a="180", choice_b="360", choice_c="90", choice_d="270", correct_choice="B"))
    questions.append(Question(text="Which blood type is universal donor?", choice_a="O+", choice_b="A-", choice_c="B+", choice_d="O-", correct_choice="D"))
    questions.append(Question(text="What planet is closest to the sun?", choice_a="Venus", choice_b="Earth", choice_c="Mercury", choice_d="Mars", correct_choice="C"))
    questions.append(Question(text="What is the largest mammal?", choice_a="Elephant", choice_b="Blue Whale", choice_c="Giraffe", choice_d="Hippo", correct_choice="B"))
    questions.append(Question(text="Which instrument has keys, pedals, and strings?", choice_a="Violin", choice_b="Guitar", choice_c="Piano", choice_d="Flute", correct_choice="C"))
    questions.append(Question(text="What is the largest desert in the world?", choice_a="Gobi", choice_b="Sahara", choice_c="Antarctica", choice_d="Arctic", correct_choice="C"))
    questions.append(Question(text="What is the smallest prime number?", choice_a="1", choice_b="2", choice_c="3", choice_d="0", correct_choice="B"))
    questions.append(Question(text="What is the longest river in the world?", choice_a="Amazon", choice_b="Yangtze", choice_c="Nile", choice_d="Mississippi", correct_choice="C"))
    questions.append(Question(text="How many sides does a hexagon have?", choice_a="5", choice_b="6", choice_c="7", choice_d="8", correct_choice="B"))
    questions.append(Question(text="Which sport uses a bat and ball?", choice_a="Soccer", choice_b="Tennis", choice_c="Baseball", choice_d="Basketball", correct_choice="C"))
    questions.append(Question(text="Who invented the telephone?", choice_a="Newton", choice_b="Edison", choice_c="Bell", choice_d="Tesla", correct_choice="C"))
    questions.append(Question(text="How many players on a soccer team?", choice_a="9", choice_b="10", choice_c="11", choice_d="12", correct_choice="C"))
    questions.append(Question(text="What is the freezing point of water in Fahrenheit?", choice_a="0", choice_b="32", choice_c="100", choice_d="212", correct_choice="B"))
    questions.append(Question(text="Which planet has rings?", choice_a="Mars", choice_b="Saturn", choice_c="Earth", choice_d="Venus", correct_choice="B"))
    questions.append(Question(text="Which ocean lies between Africa and Australia?", choice_a="Atlantic", choice_b="Pacific", choice_c="Indian", choice_d="Arctic", correct_choice="C"))
    questions.append(Question(text="What is the main language in Brazil?", choice_a="Spanish", choice_b="Portuguese", choice_c="English", choice_d="French", correct_choice="B"))
    questions.append(Question(text="Which continent is the largest?", choice_a="Africa", choice_b="Asia", choice_c="Europe", choice_d="North America", correct_choice="B"))
    questions.append(Question(text="Which gas do humans exhale?", choice_a="Oxygen", choice_b="Hydrogen", choice_c="Carbon Dioxide", choice_d="Helium", correct_choice="C"))
    questions.append(Question(text="How many letters are in the English alphabet?", choice_a="24", choice_b="25", choice_c="26", choice_d="27", correct_choice="C"))
    questions.append(Question(text="Which bird is known for its colorful feathers and tail?", choice_a="Parrot", choice_b="Peacock", choice_c="Eagle", choice_d="Swan", correct_choice="B"))
    questions.append(Question(text="What is the chemical symbol for gold?", choice_a="Au", choice_b="Ag", choice_c="Gd", choice_d="Go", correct_choice="A"))
    db.session.add_all(questions)
    db.session.commit()
def main():
    app = create_app()
    with app.app_context():
        db.create_all()
        with app.test_request_context():
            if '_user_id' in session:
                session.pop('_user_id', None)
                session.modified = True
                print("ℹ️ Login session forcibly cleared on app startup.")
        seed_questions()
        existing_admin = User.query.filter_by(username='admin').first()
        if not existing_admin:
            admin = User(username='admin', role='admin')
            admin.set_password('Password123')
            db.session.add(admin)
            db.session.commit()
        else:
            pass
        print("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nApp running! Open \033[93mhttp://127.0.0.1:5001/\033[0m to get started.")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5001)), debug=True)
if __name__ == '__main__':
    main()