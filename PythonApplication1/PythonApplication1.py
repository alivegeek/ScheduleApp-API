
from bottle import Bottle, request, response, HTTPError, run
from twilio.rest import Client
import uuid
import time
import bcrypt
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

app = Bottle()

# Twilio configuration
twilio_account_sid = 'your_account_sid'
twilio_auth_token = 'your_auth_token'
twilio_phone_number = 'your_twilio_phone_number'

client = Client(twilio_account_sid, twilio_auth_token)

# SQLite and SQLAlchemy configuration
engine = create_engine('sqlite:///users.db')
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    
    phone_number = Column(String, primary_key=True)
    verification_code = Column(String)
    session_id = Column(String)
    session_expiration = Column(Integer)

Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)

@app.post('/signup')
def signup():
    phone_number = request.json.get('phone_number')

    # Check if the phone number is already in use
    db_session = Session()
    user = db_session.query(User).filter_by(phone_number=phone_number).first()
    if user:
        raise HTTPError(400, "Phone number already in use")

    # Send a verification code to the user's phone number
    verification_code = client.messages.create(
        body='Your verification code is: 123456',
        from_=twilio_phone_number,
        to=phone_number
    )

    # Store the verification code in the database
    user = User(phone_number=phone_number, verification_code='123456')
    db_session.add(user)
    db_session.commit()

    return {"message": "Verification code sent"}

@app.post('/verify')
def verify():
    phone_number = request.json.get('phone_number')
    verification_code = request.json.get('verification_code')

    # Retrieve the user from the database
    db_session = Session()
    user = db_session.query(User).filter_by(phone_number=phone_number).first()
    
    if not user or user.verification_code != verification_code:
        raise HTTPError(401, "Invalid verification code")

    # Generate a unique session ID, hash it, and store it in the database
    session_id = str(uuid.uuid4())
    hashed_session_id = bcrypt.hashpw(session_id.encode(), bcrypt.gensalt()).decode()
    user.session_id = hashed_session_id
    user.session_expiration = int(time.time()) + 24*60*60  # The session will expire after 24 hours
    db_session.commit()

    # Set the session ID in a secure, http-only cookie
    response.set_cookie('session_id', session_id, secure=True, httponly=True)

    return {"message": "Phone number verified and user logged in"}

@app.get('/profile')
def profile():
    # Get the session ID from the cookie
    session_id = request.get_cookie('session_id')

    # Hash the session ID and retrieve the user from the database
    hashed_session_id = bcrypt.hashpw(session_id.encode(), bcrypt.gensalt()).decode()
    db_session = Session()
    user = db_session.query(User).filter_by(session_id=hashed_session_id).first()

    # Check if the session ID is valid and has not expired
    if not user or user.session_expiration < int(time.time()):
        raise HTTPError(401, "Not logged in")

    return {"phone_number": user.phone_number}

run(app, host='localhost', port=8080)
