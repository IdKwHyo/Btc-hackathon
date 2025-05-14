import os
import json
import hashlib
from datetime import datetime, timedelta, timezone
import uuid
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session, render_template
from flask import Flask, request, jsonify, g, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import google.generativeai as genai

#from bitcoin_integration import BitcoinTimestamping, LightningPayments
from my_btc_utils import BitcoinTimestamping, LightningPayments
from my_btc_utils import BitcoinTimestamping
from flask import Flask, request, jsonify, session, render_template, send_file

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///bittasker.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

# Load Bitcoin and Lightning configurations from environment variables
app.config['BITCOIN_TESTNET'] = os.environ.get('BITCOIN_TESTNET', 'True') == 'True'
app.config['BLOCKCHAIN_API_KEY'] = os.environ.get('BLOCKCHAIN_API_KEY')
app.config['LIGHTNING_NODE_URL'] = os.environ.get('LIGHTNING_NODE_URL')
app.config['LIGHTNING_API_KEY'] = os.environ.get('LIGHTNING_API_KEY')
app.config['LIGHTNING_MACAROON'] = os.environ.get('LIGHTNING_MACAROON')

# Configure Gemini AI API
app.config['GEMINI_API_KEY'] = os.environ.get('GEMINI_API_KEY')
genai.configure(api_key=app.config['GEMINI_API_KEY'])

# Setup database
db = SQLAlchemy(app)

# Setup CORS
CORS(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize Bitcoin timestamping and Lightning payments
bitcoin_timestamper = BitcoinTimestamping(app)
lightning_payments = LightningPayments(app)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    lightning_address = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tasks = db.relationship('Task', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    is_completed = db.Column(db.Boolean, default=False)
    priority = db.Column(db.Integer, default=1)  # 1=low, 2=medium, 3=high
    due_date = db.Column(db.DateTime, nullable=True)
    estimated_time = db.Column(db.Integer, nullable=True)  # Minutes
    tags = db.Column(db.String(200), nullable=True)
    
    # Blockchain verification data
    blockchain_verified = db.Column(db.Boolean, default=False)
    verification_hash = db.Column(db.String(64), nullable=True)
    timestamp_data = db.Column(db.Text, nullable=True)  # JSON string with timestamp info
    
    # Lightning reward
    reward_sats = db.Column(db.Integer, default=0)  # Amount in satoshis
    reward_paid = db.Column(db.Boolean, default=False)
    payment_hash = db.Column(db.String(64), nullable=True)

class AICoachInsight(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    insight_type = db.Column(db.String(50), nullable=False)  # productivity, focus, habits, etc.
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref='ai_insights', lazy=True)

class TeamMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='member')  # member, admin
    
    user = db.relationship('User', backref='memberships', lazy=True)
    team = db.relationship('Team', backref='memberships', lazy=True)

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    lightning_balance = db.Column(db.Integer, default=0)  # Team reward pool in sats

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# AI Coach class for managing Gemini 1.5 integration
class AIProductivityCoach:
    def __init__(self):
        self.model = genai.GenerativeModel('gemini-1.5-pro')

    def analyze_task_patterns(self, user_id):
        """Analyze user task patterns and generate insights"""
        # Get user tasks from the past 30 days
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        user_tasks = Task.query.filter_by(user_id=user_id).filter(Task.created_at >= thirty_days_ago).all()
        
        if len(user_tasks) < 5:
            return {"message": "Need more task data to generate meaningful insights"}
        
        # Prepare task data for AI analysis
        task_data = []
        for task in user_tasks:
            task_info = {
                "title": task.title,
                "created_at": task.created_at.isoformat(),
                "completed_at": task.completed_at.isoformat() if task.completed_at else None,
                "is_completed": task.is_completed,
                "priority": task.priority,
                "estimated_time": task.estimated_time,
                "tags": task.tags
            }
            task_data.append(task_info)
        
        # Query the AI model
        prompt = f"""
        As an AI productivity coach, analyze this user's task history and provide insights:
        {json.dumps(task_data)}
        
        Please analyze and provide insights about:
        1. Task completion patterns (time of day, day of week)
        2. Priority management effectiveness
        3. Time estimation accuracy
        4. Most and least productive categories (from tags)
        5. Specific productivity suggestions based on their patterns
        
        Format your response as a JSON object with these keys:
        - completion_patterns
        - priority_management
        - time_estimation
        - productive_categories
        - suggestions
        """
        
        try:
            response = self.model.generate_content(prompt)
            
            if not response.text:
                return {"error": "Failed to generate AI coaching insights"}
                
            # Extract the JSON from the response
            insights = json.loads(response.text.strip())
            
            # Store the insights in the database
            for insight_type, content in insights.items():
                new_insight = AICoachInsight(
                    user_id=user_id,
                    insight_type=insight_type,
                    content=json.dumps(content) if isinstance(content, dict) else content
                )
                db.session.add(new_insight)
            
            db.session.commit()
            return insights
            
        except Exception as e:
            app.logger.error(f"Error generating AI insights: {str(e)}")
            return {"error": f"Failed to generate insights: {str(e)}"}
    
    def suggest_time_blocks(self, user_id, date_str):
        """Generate suggested time blocks for tasks on a specific date"""
        try:
            # Get incomplete tasks
            incomplete_tasks = Task.query.filter_by(user_id=user_id, is_completed=False).all()
            
            if not incomplete_tasks:
                return {"message": "No incomplete tasks to schedule"}
            
            # Format tasks for AI analysis
            task_list = []
            for task in incomplete_tasks:
                task_info = {
                    "id": task.id,
                    "title": task.title,
                    "priority": task.priority,
                    "estimated_time": task.estimated_time,
                    "due_date": task.due_date.isoformat() if task.due_date else None,
                    "tags": task.tags
                }
                task_list.append(task_info)
            
            prompt = f"""
            As an AI productivity coach, create an optimal schedule of time blocks for these tasks on {date_str}:
            {json.dumps(task_list)}
            
            Create time blocks from 9 AM to 6 PM, accounting for:
            1. Task priority (higher priority tasks earlier)
            2. Estimated completion time
            3. Due dates (more urgent tasks sooner)
            4. Group similar tasks together (based on tags)
            5. Include short breaks between blocks
            
            Format your response as a JSON array of time blocks, each with:
            - start_time (HH:MM format)
            - end_time (HH:MM format)
            - task_id (from the input data)
            - task_title
            - block_type ("task" or "break")
            """
            
            response = self.model.generate_content(prompt)
            
            if not response.text:
                return {"error": "Failed to generate time blocks"}
                
            # Extract the JSON from the response
            time_blocks = json.loads(response.text.strip())
            return {"time_blocks": time_blocks}
            
        except Exception as e:
            app.logger.error(f"Error generating time blocks: {str(e)}")
            return {"error": f"Failed to generate time blocks: {str(e)}"}

    def identify_efficiency_habits(self, user_id):
        """Identify productivity habits and suggest improvements"""
        try:
            # Get all completed tasks with completion times
            completed_tasks = Task.query.filter_by(
                user_id=user_id, 
                is_completed=True
            ).filter(
                Task.completed_at.isnot(None)
            ).order_by(
                Task.completed_at.desc()
            ).limit(50).all()
            
            if len(completed_tasks) < 10:
                return {"message": "Need more completed tasks to analyze efficiency habits"}
            
            # Process tasks to find patterns
            task_data = []
            for task in completed_tasks:
                if task.created_at and task.completed_at:
                    completion_time = (task.completed_at - task.created_at).total_seconds() / 60  # minutes
                    estimated_time = task.estimated_time or 0
                    accuracy = estimated_time / completion_time if completion_time > 0 else 0
                    
                    task_info = {
                        "title": task.title,
                        "completion_time_minutes": completion_time,
                        "estimated_time": estimated_time,
                        "time_accuracy": accuracy,
                        "priority": task.priority,
                        "tags": task.tags,
                        "completed_at": task.completed_at.isoformat(),
                        "day_of_week": task.completed_at.strftime('%A')
                    }
                    task_data.append(task_info)
            
            prompt = f"""
            As an AI productivity coach, analyze this user's completed tasks to identify efficiency habits:
            {json.dumps(task_data)}
            
            Please analyze and provide insights about:
            1. When the user is most productive (time of day, day of week)
            2. Which types of tasks they complete most efficiently
            3. Time estimation accuracy patterns
            4. Potential productivity drains or bottlenecks
            5. Specific habit suggestions to improve productivity
            
            Format your response as a JSON object with these keys:
            - peak_productivity_times
            - efficient_task_types
            - estimation_accuracy
            - productivity_drains
            - habit_suggestions
            """
            
            response = self.model.generate_content(prompt)
            
            if not response.text:
                return {"error": "Failed to identify efficiency habits"}
                
            # Extract the JSON from the response
            habits = json.loads(response.text.strip())
            
            # Store as an insight
            new_insight = AICoachInsight(
                user_id=user_id,
                insight_type="efficiency_habits",
                content=json.dumps(habits)
            )
            db.session.add(new_insight)
            db.session.commit()
            
            return habits
            
        except Exception as e:
            app.logger.error(f"Error identifying efficiency habits: {str(e)}")
            return {"error": f"Failed to identify efficiency habits: {str(e)}"}

# Initialize AI coach
ai_coach = AIProductivityCoach()
def save_to_history(user_input, ai_response):
    if "chat_history" not in session:
        session["chat_history"] = []
    
    session["chat_history"].append({
        "timestamp": datetime.now().isoformat(),
        "user": user_input,
        "ai": ai_response
    })
    session.modified = True
def handle_general_conversation(query):
    try:
        response = model.generate_content(f"""
        Respond naturally to this general conversation in 1-2 sentences:
        User: {query}
        """)
        return {
            "text": response.text,
            "source": "gemini",
            "is_finance": False
        }
    except Exception as e:
        logger.error(f"Gemini error: {e}")
        return {
            "text": "I couldn't process your request. Please try again.",
            "source": "error",
            "is_finance": False
        }
# API Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
        
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    user = User(
        username=data['username'],
        email=data['email'],
        lightning_address=data.get('lightning_address')
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/api/tasks', methods=['GET'])
@login_required
def get_tasks():
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    
    result = []
    for task in tasks:
        task_data = {
            'id': task.id,
            'title': task.title,
            'description': task.description,
            'created_at': task.created_at.isoformat(),
            'completed_at': task.completed_at.isoformat() if task.completed_at else None,
            'is_completed': task.is_completed,
            'priority': task.priority,
            'due_date': task.due_date.isoformat() if task.due_date else None,
            'estimated_time': task.estimated_time,
            'tags': task.tags,
            'blockchain_verified': task.blockchain_verified,
            'reward_sats': task.reward_sats,
            'reward_paid': task.reward_paid
        }
        result.append(task_data)
    
    return jsonify(result), 200

@app.route('/api/tasks', methods=['POST'])
@login_required
def create_task():
    data = request.get_json()
    
    if not data or not data.get('title'):
        return jsonify({'error': 'Missing required title field'}), 400
    
    new_task = Task(
        title=data['title'],
        description=data.get('description'),
        user_id=current_user.id,
        priority=data.get('priority', 1),
        due_date=datetime.fromisoformat(data['due_date']) if data.get('due_date') else None,
        estimated_time=data.get('estimated_time'),
        tags=data.get('tags'),
        reward_sats=data.get('reward_sats', 0)
    )
    
    db.session.add(new_task)
    db.session.commit()
    
    return jsonify({
        'message': 'Task created successfully',
        'task': {
            'id': new_task.id,
            'title': new_task.title
        }
    }), 201

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
@login_required
def update_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first()
    
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    data = request.get_json()
    
    if 'title' in data:
        task.title = data['title']
    if 'description' in data:
        task.description = data['description']
    if 'priority' in data:
        task.priority = data['priority']
    if 'due_date' in data:
        task.due_date = datetime.fromisoformat(data['due_date']) if data['due_date'] else None
    if 'estimated_time' in data:
        task.estimated_time = data['estimated_time']
    if 'tags' in data:
        task.tags = data['tags']
    if 'reward_sats' in data:
        task.reward_sats = data['reward_sats']
    
    db.session.commit()
    
    return jsonify({'message': 'Task updated successfully'}), 200

@app.route('/api/tasks/<int:task_id>/complete', methods=['POST'])
@login_required
def complete_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first()
    
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    if task.is_completed:
        return jsonify({'error': 'Task already completed'}), 400
    
    # Mark task as completed
    task.is_completed = True
    task.completed_at = datetime.utcnow()
    
    # Create Bitcoin timestamp
    task_hash = bitcoin_timestamper.create_task_hash(task)
    task.verification_hash = task_hash
    
    # Choose timestamping method - using OpenTimestamps for better efficiency
    timestamp_result = bitcoin_timestamper.timestamp_with_opentimestamps(task_hash)
    
    if timestamp_result['success']:
        task.blockchain_verified = True
        task.timestamp_data = json.dumps(timestamp_result)
        
        # Process Lightning reward if available
        if task.reward_sats > 0 and current_user.lightning_address:
            payment_result = lightning_payments.send_reward(
                current_user.lightning_address, 
                task.reward_sats
            )
            
            if payment_result['success']:
                task.reward_paid = True
                task.payment_hash = payment_result['payment_hash']
        
        db.session.commit()
        
        return jsonify({
            'message': 'Task completed and verified on blockchain',
            'verification': {
                'hash': task_hash,
                'timestamp': timestamp_result
            },
            'reward': {
                'paid': task.reward_paid,
                'amount_sats': task.reward_sats
            }
        }), 200
    else:
        db.session.commit()
        return jsonify({
            'message': 'Task completed but blockchain verification failed',
            'error': timestamp_result.get('error', 'Unknown verification error')
        }), 200

@app.route('/api/tasks/<int:task_id>/verify', methods=['GET'])
@login_required
def verify_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first()
    
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    if not task.blockchain_verified:
        return jsonify({'error': 'Task not verified on blockchain'}), 400
    
    # Verify the timestamp
    timestamp_data = json.loads(task.timestamp_data)
    verification = bitcoin_timestamper.verify_timestamp(task.verification_hash, timestamp_data)
    
    return jsonify({
        'task_id': task.id,
        'title': task.title,
        'verification_hash': task.verification_hash,
        'verification': verification
    }), 200

@app.route('/api/coach/insights', methods=['GET'])
@login_required
def get_ai_insights():
    insights = AICoachInsight.query.filter_by(user_id=current_user.id).order_by(AICoachInsight.created_at.desc()).all()
    
    result = []
    for insight in insights:
        insight_data = {
            'id': insight.id,
            'type': insight.insight_type,
            'content': json.loads(insight.content) if insight.content[0] in ['{', '['] else insight.content,
            'created_at': insight.created_at.isoformat(),
            'is_read': insight.is_read
        }
        result.append(insight_data)
    
    return jsonify(result), 200

@app.route('/api/coach/analyze', methods=['GET'])
@login_required
def analyze_productivity():
    insights = ai_coach.analyze_task_patterns(current_user.id)
    return jsonify(insights), 200

@app.route('/api/coach/schedule', methods=['GET'])
@login_required
def get_schedule_suggestions():
    date_str = request.args.get('date', datetime.utcnow().strftime('%Y-%m-%d'))
    schedule = ai_coach.suggest_time_blocks(current_user.id, date_str)
    return jsonify(schedule), 200

@app.route('/api/coach/habits', methods=['GET'])
@login_required
def get_habit_suggestions():
    habits = ai_coach.identify_efficiency_habits(current_user.id)
    return jsonify(habits), 200

@app.route('/api/teams', methods=['GET'])
@login_required
def get_teams():
    # Get teams the user is a member of
    memberships = TeamMembership.query.filter_by(user_id=current_user.id).all()
    team_ids = [m.team_id for m in memberships]
    teams = Team.query.filter(Team.id.in_(team_ids)).all()
    
    result = []
    for team in teams:
        team_data = {
            'id': team.id,
            'name': team.name,
            'description': team.description,
            'created_at': team.created_at.isoformat(),
            'lightning_balance': team.lightning_balance,
            'role': next((m.role for m in memberships if m.team_id == team.id), None)
        }
        result.append(team_data)
    
    return jsonify(result), 200

@app.route('/api/teams', methods=['POST'])
@login_required
def create_team():
    data = request.get_json()
    
    if not data or not data.get('name'):
        return jsonify({'error': 'Missing required name field'}), 400
    
    new_team = Team(
        name=data['name'],
        description=data.get('description'),
        lightning_balance=data.get('lightning_balance', 0)
    )
    
    db.session.add(new_team)
    db.session.flush()  # Get the team ID before commit
    
    # Add current user as team admin
    membership = TeamMembership(
        user_id=current_user.id,
        team_id=new_team.id,
        role='admin'
    )
    
    db.session.add(membership)
    db.session.commit()
    
    return jsonify({
        'message': 'Team created successfully',
        'team': {
            'id': new_team.id,
            'name': new_team.name
        }
    }), 201
# Add this near your other routes in btc_app.py

@app.route('/api/placeholder/<width>/<height>')
def placeholder_image(width, height):
    try:
        from PIL import Image, ImageDraw
        img = Image.new('RGB', (int(width), int(height)), color=(73, 109, 137))
        d = ImageDraw.Draw(img)
        d.text((10,10), f"{width}x{height}", fill=(255,255,255))
        
        from io import BytesIO
        img_bytes = BytesIO()
        img.save(img_bytes, format='PNG')
        img_bytes.seek(0)
        
        return send_file(img_bytes, mimetype='image/png')
    except ImportError:
        # Fallback if PIL is not installed
        return "Placeholder image", 404

@app.route('/api/health', methods=['GET'])
def health_check():
    """API health check endpoint"""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    }), 200

# Update your login route to return a token
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid username or password'}), 401
    
    # Generate a simple token (in production, use JWT or similar)
    token = hashlib.sha256(f"{user.id}{datetime.utcnow().isoformat()}".encode()).hexdigest()
    
    login_user(user)
    
    return jsonify({
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'lightning_address': user.lightning_address
        }
    }), 200
@app.route('/api/teams/<int:team_id>/members', methods=['POST'])
@login_required
def add_team_member(team_id):
    # Check if user is admin of the team
    membership = TeamMembership.query.filter_by(
        user_id=current_user.id, 
        team_id=team_id, 
        role='admin'
    ).first()
    
    if not membership:
        return jsonify({'error': 'Not authorized to add members to this team'}), 403
    
    data = request.get_json()
    
    if not data or not data.get('username'):
        return jsonify({'error': 'Missing required username field'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Check if user is already a member
    existing = TeamMembership.query.filter_by(user_id=user.id, team_id=team_id).first()
    
    if existing:
        return jsonify({'error': 'User is already a member of this team'}), 400
    
    # Add member
    new_membership = TeamMembership(
        user_id=user.id,
        team_id=team_id,
        role=data.get('role', 'member')
    )
    
    db.session.add(new_membership)
    db.session.commit()
    
    return jsonify({'message': 'Team member added successfully'}), 201
@app.route('/get-chat-history', methods=['GET'])
def get_chat_history():
    return jsonify(session.get("chat_history", []))
@app.route('/api/teams/<int:team_id>/tasks', methods=['GET'])
@login_required
def get_team_tasks(team_id):
    # Check if user is a member of the team
    membership = TeamMembership.query.filter_by(
        user_id=current_user.id, 
        team_id=team_id
    ).first()
    
    if not membership:
        return jsonify({'error': 'Not a member of this team'}), 403
    
    # Get all members of the team
    memberships = TeamMembership.query.filter_by(team_id=team_id).all()
    user_ids = [m.user_id for m in memberships]
    
    # Get completed tasks for all team members
    tasks = Task.query.filter(
        Task.user_id.in_(user_ids),
        Task.is_completed == True,
        Task.blockchain_verified == True
    ).order_by(Task.completed_at.desc()).all()
    
    result = []
    for task in tasks:
        user = User.query.get(task.user_id)
        
        task_data = {
            'id': task.id,
            'title': task.title,
            'user': user.username,
            'completed_at': task.completed_at.isoformat() if task.completed_at else None,
            'verification_hash': task.verification_hash,
            'blockchain_verified': task.blockchain_verified
        }
        result.append(task_data)
    
    return jsonify(result), 200
@app.route("/")
def home():
    return render_template("index5.html") 


# Initialize the database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG', 'True') == 'True', host='0.0.0.0')