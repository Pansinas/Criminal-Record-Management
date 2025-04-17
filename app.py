import streamlit as st
from pymongo import MongoClient
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
import pandas as pd
import plotly.express as px

# Load environment variables
load_dotenv()

# Initialize session state
def init_session_state():
    if "user_type" not in st.session_state:
        st.session_state.user_type = None
    if "username" not in st.session_state:
        st.session_state.username = None
    if "login_attempts" not in st.session_state:
        st.session_state.login_attempts = 0
    if "page" not in st.session_state:
        st.session_state.page = "login"

init_session_state()

# MongoDB Atlas connection with error handling
try:
    MONGODB_URI = os.getenv("MONGODB_URI", "mongodb+srv://pansinas:<password>@cluster0.novrfdr.mongodb.net/crime_record_db?retryWrites=true&w=majority")
    
    client = MongoClient(
        MONGODB_URI,
        serverSelectionTimeoutMS=5000,
        socketTimeoutMS=30000,
        connectTimeoutMS=30000
    )
    
    client.server_info()
    db = client["crime_record_db"]
    users_col = db["users"]
    crimes_col = db["crimes"]
    complaints_col = db["complaints"]
    access_requests_col = db["access_requests"]
    
except Exception as e:
    st.error(f"Failed to connect to MongoDB Atlas: {str(e)}")
    st.error("Please check your connection settings")
    st.stop()

# Utility functions
def validate_aadhar(aadhar):
    return re.match(r"^\d{12}$", aadhar) is not None

def validate_phone(phone):
    return re.match(r"^\d{10}$", phone) is not None

def get_next_id(collection, id_field):
    last_doc = collection.find_one(sort=[(id_field, -1)])
    return last_doc[id_field] + 1 if last_doc else 1

# Authentication functions
def login(username, password, user_type):
    if st.session_state.login_attempts >= 3:
        st.error("Too many failed attempts. Please try again later.")
        return False
    
    if user_type == "admin":
        if username == "admin123" and password == "Admin1226":
            st.session_state.login_attempts = 0
            return True
        else:
            st.session_state.login_attempts += 1
            return False
    
    user = users_col.find_one({"username": username, "type": user_type})
    if user and check_password_hash(user["password"], password):
        st.session_state.login_attempts = 0
        return True
    
    st.session_state.login_attempts += 1
    return False

def register_user(username, password, user_type="public"):
    if users_col.find_one({"username": username}):
        return False, "Username already exists"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    hashed_pw = generate_password_hash(password)
    users_col.insert_one({
        "username": username,
        "password": hashed_pw,
        "type": user_type,
        "created_at": datetime.now()
    })
    return True, "Registration successful! Please log in."

def request_department_access(username, password):
    if users_col.find_one({"username": username}):
        return False, "Username already exists"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    access_requests_col.insert_one({
        "username": username,
        "password": generate_password_hash(password),
        "requested_at": datetime.now(),
        "status": "pending"
    })
    return True, "Department access requested. An admin will review your application."

def approve_department_user(request_id):
    request = access_requests_col.find_one({"_id": request_id})
    if not request:
        return False, "Request not found"
    
    users_col.insert_one({
        "username": request["username"],
        "password": request["password"],
        "type": "department",
        "created_at": datetime.now()
    })
    
    access_requests_col.delete_one({"_id": request_id})
    return True, f"Approved {request['username']} as department user."

def logout():
    st.session_state.user_type = None
    st.session_state.username = None
    st.session_state.page = "login"

# Page components
def login_page():
    st.title("🔐 Crime Record Management System - Login")
    
    login_type = st.selectbox("Login as", ["public", "department", "admin"])
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if login(username, password, login_type):
            st.session_state.username = username
            st.session_state.user_type = login_type
            st.session_state.page = "dashboard"
            st.rerun()
        else:
            st.error("Invalid credentials")
    
    if st.button("Go to Registration"):
        st.session_state.page = "register"
        st.rerun()

def register_page():
    st.title("📝 User Registration")
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    is_dept_request = st.checkbox("Request Department Access (Requires Admin Approval)")
    
    if st.button("Register"):
        if password != confirm_password:
            st.error("Passwords do not match")
        elif len(password) < 8:
            st.error("Password must be at least 8 characters")
        else:
            if is_dept_request:
                success, message = request_department_access(username, password)
            else:
                success, message = register_user(username, password)
            
            if success:
                st.success(message)
                st.session_state.page = "login"
                st.rerun()
            else:
                st.error(message)
    
    if st.button("Back to Login"):
        st.session_state.page = "login"
        st.rerun()

def public_dashboard():
    st.sidebar.title(f"Public Dashboard")
    menu = st.sidebar.selectbox("Menu", ["Search Crimes", "File Complaint", "My Complaints", "Logout"])
    
    if menu == "Search Crimes":
        st.header("🔎 Search Crimes")
        # Implement crime search functionality
        st.write("Crime search functionality would go here")
    
    elif menu == "File Complaint":
        st.header("📝 File Complaint")
        # Implement complaint filing
        st.write("Complaint filing form would go here")
    
    elif menu == "My Complaints":
        st.header("📋 My Complaints")
        # Show user's complaints
        st.write("List of user's complaints would go here")
    
    elif menu == "Logout":
        logout()
        st.rerun()

def department_dashboard():
    st.sidebar.title(f"Department Dashboard")
    menu = st.sidebar.selectbox("Menu", ["Manage Complaints", "Manage Crimes", "Analytics", "Logout"])
    
    if menu == "Manage Complaints":
        st.header("📩 Manage Complaints")
        # Implement complaint management
        st.write("Complaint management interface would go here")
    
    elif menu == "Manage Crimes":
        st.header("🔧 Manage Crimes")
        # Implement crime management
        st.write("Crime management interface would go here")
    
    elif menu == "Analytics":
        st.header("📊 Crime Analytics")
        # Implement analytics
        st.write("Analytics dashboard would go here")
    
    elif menu == "Logout":
        logout()
        st.rerun()

def admin_dashboard():
    st.sidebar.title(f"Admin Dashboard")
    menu = st.sidebar.selectbox("Menu", ["Approve Requests", "Manage Users", "System Logs", "Logout"])
    
    if menu == "Approve Requests":
        st.header("🛂 Approve Department Requests")
        # Implement request approval
        st.write("Department request approval interface would go here")
    
    elif menu == "Manage Users":
        st.header("👥 User Management")
        # Implement user management
        st.write("User management interface would go here")
    
    elif menu == "System Logs":
        st.header("📜 System Activity")
        # Implement system logs
        st.write("System activity logs would go here")
    
    elif menu == "Logout":
        logout()
        st.rerun()

# Main app router
def main():
    if st.session_state.page == "login":
        login_page()
    elif st.session_state.page == "register":
        register_page()
    elif st.session_state.user_type == "public":
        public_dashboard()
    elif st.session_state.user_type == "department":
        department_dashboard()
    elif st.session_state.user_type == "admin":
        admin_dashboard()

if __name__ == "__main__":
    main()
