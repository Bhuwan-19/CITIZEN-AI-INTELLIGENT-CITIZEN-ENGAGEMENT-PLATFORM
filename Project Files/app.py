# app.py - Main Flask Application
from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify, session
import sqlite3
import hashlib
import secrets
from typing import Any, List, Optional, Dict, Tuple
import datetime
import json
import os
from pathlib import Path
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.llms.base import LLM
from typing import Any, List
from langchain_ibm import WatsonxLLM
from functools import wraps

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: python-dotenv not installed. Install it with: pip install python-dotenv")
    print("Make sure to set environment variables manually.")

# Create directories if they don't exist
Path("templates").mkdir(exist_ok=True)
Path("static").mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")

# Fallback responses when AI is not available
FALLBACK_RESPONSES = [
    "I understand your query about Indian government services. For the most accurate and up-to-date information, I recommend visiting the official government portal at india.gov.in or contacting your nearest government office.",
    "Thank you for your question about citizen services. For specific legal or procedural guidance, please visit the official government website or contact your local government office for assistance.",
    "I appreciate your inquiry about Indian government services. For detailed information and official procedures, please refer to the relevant government department's official website or visit your nearest government office.",
    "Your question about government services is important. For official guidance and procedures, I recommend checking the official government portal or contacting the appropriate government department directly.",
    "Thank you for reaching out about government services. For the most current and accurate information, please visit the official government website or contact your local government office."
]

class CitizenAIDatabase:
    def __init__(self, db_path="citizen_ai.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize all required tables"""
        conn = sqlite3.connect(self.db_path)
        
        # Users table (added role column)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT DEFAULT 'citizen', -- citizen or govt
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Sessions table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_token TEXT UNIQUE NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Chat history table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS chat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                user_message TEXT NOT NULL,
                ai_response TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Sentiment analysis table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sentiment_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                feedback_text TEXT NOT NULL,
                sentiment TEXT NOT NULL,
                confidence REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _hash_password(self, password: str, salt: Optional[str] = None) -> tuple:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(32)
        
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode('utf-8'), 
            salt.encode('utf-8'), 
            100000
        )
        return password_hash.hex(), salt
    
    def register_user(self, username: str, email: str, password: str, full_name: str, role: str = "citizen") -> Dict:
        """Register a new user"""
        if len(password) < 8:
            return {"success": False, "message": "Password must be at least 8 characters"}
        
        password_hash, salt = self._hash_password(password)
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, salt, full_name, role)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, email, password_hash, salt, full_name, role))
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            
            return {"success": True, "message": "Registration successful", "user_id": user_id}
        
        except sqlite3.IntegrityError as e:
            if "username" in str(e):
                return {"success": False, "message": "Username already exists"}
            elif "email" in str(e):
                return {"success": False, "message": "Email already exists"}
            else:
                return {"success": False, "message": "Registration failed"}
    
    def login_user(self, username: str, password: str) -> Dict:
        """Authenticate user and create session"""
        conn = sqlite3.connect(self.db_path)
        
        user_data = conn.execute('''
            SELECT id, username, password_hash, salt, is_active, full_name, role 
            FROM users WHERE username = ? OR email = ?
        ''', (username, username)).fetchone()
        
        if not user_data or not user_data[4]:
            conn.close()
            return {"success": False, "message": "Invalid credentials"}
        
        user_id, db_username, stored_hash, salt, is_active, full_name, role = user_data
        
        input_hash, _ = self._hash_password(password, salt)
        
        if input_hash == stored_hash:
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.datetime.now() + datetime.timedelta(days=7)
            
            conn.execute('''
                INSERT INTO sessions (user_id, session_token, expires_at)
                VALUES (?, ?, ?)
            ''', (user_id, session_token, expires_at))
            
            conn.execute('''
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
            ''', (user_id,))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "session_token": session_token,
                "user_id": user_id,
                "username": db_username,
                "full_name": full_name,
                "role": role
            }
        else:
            conn.close()
            return {"success": False, "message": "Invalid credentials"}
    
    def verify_session(self, session_token: str) -> Optional[Dict]:
        """Verify session token"""
        if not session_token:
            return None
            
        conn = sqlite3.connect(self.db_path)
        
        result = conn.execute('''
            SELECT s.user_id, u.username, s.expires_at, u.is_active, u.full_name, u.role
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ? AND s.is_active = 1
        ''', (session_token,)).fetchone()
        
        conn.close()
        
        if not result:
            return None
        
        user_id, username, expires_at, is_active, full_name, role = result
        expires_at = datetime.datetime.fromisoformat(expires_at)
        
        if expires_at < datetime.datetime.now() or not is_active:
            return None
        
        return {"user_id": user_id, "username": username, "full_name": full_name, "role": role}
    
    def save_chat(self, user_id: int, user_message: str, ai_response: str):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            INSERT INTO chat_history (user_id, user_message, ai_response)
            VALUES (?, ?, ?)
        ''', (user_id, user_message, ai_response))
        conn.commit()
        conn.close()
    
    def save_sentiment(self, user_id: int, feedback_text: str, sentiment: str, confidence: float = 0.0):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            INSERT INTO sentiment_analysis (user_id, feedback_text, sentiment, confidence)
            VALUES (?, ?, ?, ?)
        ''', (user_id, feedback_text, sentiment, confidence))
        conn.commit()
        conn.close()
    
    def get_chat_history(self, user_id: int, limit: int = 10):
        conn = sqlite3.connect(self.db_path)
        results = conn.execute('''
            SELECT user_message, ai_response, timestamp
            FROM chat_history
            WHERE user_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (user_id, limit)).fetchall()
        conn.close()
        return results
    
    def get_sentiment_stats(self):
        conn = sqlite3.connect(self.db_path)
        results = conn.execute('''
            SELECT sentiment, COUNT(*) as count
            FROM sentiment_analysis
            GROUP BY sentiment
        ''').fetchall()
        conn.close()
        return dict(results)
    
    def get_all_users(self):
        """Get all registered users"""
        conn = sqlite3.connect(self.db_path)
        results = conn.execute('''
            SELECT id, username, email, full_name, role, created_at, last_login, is_active
            FROM users
            ORDER BY created_at DESC
        ''').fetchall()
        conn.close()
        
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2],
                "full_name": row[3],
                "role": row[4],
                "created_at": row[5],
                "last_login": row[6],
                "is_active": bool(row[7])
            })
        return users
    
    def get_all_feedback(self):
        """Get all feedback from all users"""
        conn = sqlite3.connect(self.db_path)
        results = conn.execute('''
            SELECT sa.id, sa.user_id, u.full_name, sa.feedback_text, sa.sentiment, 
                   sa.confidence, sa.timestamp
            FROM sentiment_analysis sa
            JOIN users u ON sa.user_id = u.id
            ORDER BY sa.timestamp DESC
        ''').fetchall()
        conn.close()
        
        feedback_list = []
        for row in results:
            feedback_list.append({
                "id": row[0],
                "user_id": row[1],
                "user_name": row[2],
                "feedback_text": row[3],
                "sentiment": row[4],
                "confidence": row[5],
                "timestamp": row[6]
            })
        return feedback_list

# Initialize database
db = CitizenAIDatabase()

# IBM Watsonx configuration
WATSONX_URL = os.getenv("WATSONX_URL")
WATSONX_APIKEY = os.getenv("WATSONX_APIKEY")
WATSONX_PROJECT_ID = os.getenv("WATSONX_PROJECT_ID")

class SimpleCitizenAI:
    def __init__(self):
        self.prompt_template = self.create_prompt_template()
        try:
            self.llm = WatsonxLLM(
                model_id=os.getenv("WATSONX_MODEL_ID"),
                url=WATSONX_URL,
                apikey=WATSONX_APIKEY,
                project_id=WATSONX_PROJECT_ID,
                params={
                    "decoding_method": "greedy",
                    "max_new_tokens": 500,
                    "temperature": 0.7
                }
            )
        except:
            self.llm = None

    def create_prompt_template(self):
        return PromptTemplate(
            input_variables=["user_question"],
            template="""You are Citizen AI, a smart assistant for Indian citizens...
User Question: {user_question}
Provide a helpful, actionable response focused on Indian context and regulations:"""
        )

    def generate_response(self, user_message: str) -> str:
        try:
            if self.llm is None:
                return secrets.choice(FALLBACK_RESPONSES)
                
            prompt = self.prompt_template.format(user_question=user_message)
            response = self.llm(prompt)
            return response.strip()
        except Exception as e:
            return secrets.choice(FALLBACK_RESPONSES)

ai = SimpleCitizenAI()

def analyse_sentiment(text: str):
    positive_words = ['good', 'great', 'excellent', 'amazing', 'wonderful', 'fantastic', 
                      'satisfied', 'happy', 'pleased', 'impressed', 'helpful', 'efficient']
    negative_words = ['bad', 'terrible', 'awful', 'horrible', 'disappointed', 'frustrated',
                      'angry', 'unsatisfied', 'poor', 'waste', 'useless', 'slow']
    text_lower = text.lower()
    positive_count = sum(1 for word in positive_words if word in text_lower)
    negative_count = sum(1 for word in negative_words if word in text_lower)
    if positive_count > negative_count:
        return "Positive", min(0.6 + (positive_count - negative_count) * 0.1, 1.0)
    elif negative_count > positive_count:
        return "Negative", min(0.6 + (negative_count - positive_count) * 0.1, 1.0)
    return "Neutral", 0.5

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.cookies.get('session_token')
        user = db.verify_session(session_token)
        if not user:
            return redirect(url_for('login_page'))
        return f(user, *args, **kwargs)
    return decorated_function

def govt_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.cookies.get('session_token')
        # Check if it's a hardcoded govt session
        if session_token in govt_sessions:
            user = govt_sessions[session_token]
            return f(user, *args, **kwargs)
        
        # Check if it's a database session
        user = db.verify_session(session_token)
        if not user or user["role"] != "govt":
            return redirect(url_for('login_page'))
        return f(user, *args, **kwargs)
    return decorated_function

# Global variable for government sessions
govt_sessions = {}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        
        result = db.register_user(username, email, password, full_name, role="citizen")
        if result["success"]:
            return redirect(url_for('login_page', message='Registration successful'))
        return render_template('register.html', error=result["message"])
    
    return render_template('register.html')

@app.route('/login', methods=['GET'])
def login_page():
    message = request.args.get('message')
    return render_template('login.html', message=message)

@app.route('/login/citizen', methods=['POST'])
def login_citizen():
    username = request.form.get('username')
    password = request.form.get('password')
    
    result = db.login_user(username, password)
    if result["success"] and result["role"] == "citizen":
        response = make_response(redirect(url_for('dashboard')))
        response.set_cookie('session_token', result["session_token"], httponly=True)
        return response
    return render_template('login.html', error="Invalid citizen credentials")

@app.route('/login/govt', methods=['POST'])
def login_govt():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Hardcoded government credentials
    if username == "govt" and password == "1234":
        session_token = secrets.token_hex(16)
        response = make_response(redirect(url_for('admin_dashboard')))
        response.set_cookie('session_token', session_token, httponly=True)
        
        # Store the session in memory
        govt_sessions[session_token] = {
            "user_id": 0, 
            "username": "govt_admin", 
            "full_name": "Government Administrator", 
            "role": "govt"
        }
        
        return response
    
    return render_template('login.html', error="Invalid government credentials")

@app.route('/dashboard')
@login_required
def dashboard(user):
    if user["role"] == "govt":
        return redirect(url_for('admin_dashboard'))
    
    # Get chat history
    chat_history = db.get_chat_history(user["user_id"], 5)
    
    # Get sentiment stats for the user
    conn = sqlite3.connect(db.db_path)
    sentiment_stats = conn.execute('''
        SELECT sentiment, COUNT(*) as count 
        FROM sentiment_analysis 
        WHERE user_id = ?
        GROUP BY sentiment
    ''', (user["user_id"],)).fetchall()
    conn.close()
    
    # Convert to dictionary
    sentiment_dict = {row[0]: row[1] for row in sentiment_stats}
    
    # Get recent feedback for the user
    conn = sqlite3.connect(db.db_path)
    recent_feedback = conn.execute('''
        SELECT feedback_text, sentiment, timestamp 
        FROM sentiment_analysis 
        WHERE user_id = ? 
        ORDER BY timestamp DESC 
        LIMIT 5
    ''', (user["user_id"],)).fetchall()
    conn.close()
    
    # Format feedback data
    formatted_feedback = []
    for feedback in recent_feedback:
        # Get initials for avatar
        initials = ''.join([name[0] for name in user["full_name"].split()[:2]]).upper()
        
        # Format date
        feedback_date = datetime.datetime.strptime(feedback[2], '%Y-%m-%d %H:%M:%S')
        formatted_date = feedback_date.strftime('%b %d, %Y, %I:%M %p')
        
        formatted_feedback.append({
            'text': feedback[0],
            'sentiment': feedback[1],
            'date': formatted_date,
            'initials': initials
        })
    
    return render_template('dashboard.html', 
                         user=user, 
                         chat_history=chat_history,
                         sentiment_stats=sentiment_dict,
                         recent_feedback=formatted_feedback)

@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat_page(user):
    if request.method == 'POST':
        message = request.form.get('message')
        ai_response = ai.generate_response(message)
        db.save_chat(user["user_id"], message, ai_response)
        return render_template('chat.html', user=user, user_message=message, ai_response=ai_response)
    return render_template('chat.html', user=user)

@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback_page(user):
    if request.method == 'POST':
        feedback = request.form.get('feedback')
        sentiment, confidence = analyse_sentiment(feedback)
        db.save_sentiment(user["user_id"], feedback, sentiment, confidence)
        return render_template('feedback.html', user=user, success="Thank you for your feedback!", sentiment=sentiment)
    return render_template('feedback.html', user=user)

@app.route('/admin')
@govt_login_required
def admin_dashboard(user):
    # Get all users
    all_users = db.get_all_users()
    
    # Get all feedback
    all_feedback = db.get_all_feedback()
    
    # Get sentiment statistics
    sentiment_stats = db.get_sentiment_stats()
    
    return render_template('admin_dashboard.html', 
                         user=user, 
                         all_users=all_users,
                         all_feedback=all_feedback,
                         sentiment_stats=sentiment_stats)

@app.route('/logout')
def logout():
    session_token = request.cookies.get('session_token')
    if session_token in govt_sessions:
        del govt_sessions[session_token]
    
    response = make_response(redirect(url_for('home')))
    response.delete_cookie('session_token')
    return response

if __name__ == '__main__':
    app.run(debug=True, port=5001)