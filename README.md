# Crime Record Management System

A Streamlit-based application for managing crime records with MongoDB backend.

## Features
- Public user complaint filing
- Admin dashboard for management
- Secure authentication
- Crime analytics

## Setup
1. Clone the repository
2. Create `.env` file from `.env.sample`
3. Install dependencies: `pip install -r requirements.txt`
4. Run: `streamlit run app/main.py`

## Security
- All passwords are hashed
- MongoDB connection secured with TLS
- Rate limiting on authentication
