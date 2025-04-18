import streamlit as st
from pymongo import MongoClient
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
import pandas as pd
import plotly.express as px
import re

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
    if "last_login_attempt" not in st.session_state:
        st.session_state.last_login_attempt = None

init_session_state()

# MongoDB Atlas connection
def get_db_connection():
    try:
        # Using your password (replace with environment variable in production)
        client = MongoClient(
            "mongodb+srv://pansinas:pansinas@cluster0.novrfdr.mongodb.net/crime_record_db?retryWrites=true&w=majority&appName=Cluster0",
            serverSelectionTimeoutMS=5000,
            socketTimeoutMS=30000,
            connectTimeoutMS=10000
        )
        client.server_info()  # Test connection
        return client["crime_record_db"]
    except Exception as e:
        st.error(f"⚠️ Database connection failed: {str(e)}")
        st.error("Please check:")
        st.error("1. Internet connection")
        st.error("2. MongoDB Atlas cluster status")
        st.error("3. IP whitelisting in Atlas Network Access")
        st.stop()

db = get_db_connection()
users_col = db["users"]
crimes_col = db["crimes"]
complaints_col = db["complaints"]
access_requests_col = db["access_requests"]

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
        if datetime.now() - st.session_state.last_login_attempt < timedelta(minutes=5):
            st.error("🔒 Account temporarily locked. Try again after 5 minutes.")
            return False
    
    if user_type == "admin":
        if username == "admin123" and password == "Admin1226":
            st.session_state.login_attempts = 0
            return True
    
    user = users_col.find_one({"username": username, "type": user_type})
    if user and check_password_hash(user["password"], password):
        st.session_state.login_attempts = 0
        return True
    
    st.session_state.login_attempts += 1
    st.session_state.last_login_attempt = datetime.now()
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
    return True, "Registration successful!"

def logout():
    st.session_state.user_type = None
    st.session_state.username = None
    st.session_state.page = "login"

# Page components
def login_page():
    st.title("🔐 Crime Record Management System")
    
    with st.container(border=True):
        login_type = st.selectbox("Login as", ["public", "department", "admin"])
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login", type="primary"):
            if login(username, password, login_type):
                st.session_state.username = username
                st.session_state.user_type = login_type
                st.session_state.page = "dashboard"
                st.rerun()
            else:
                st.error("Invalid credentials")
        
        cols = st.columns(2)
        with cols[0]:
            if st.button("Register", use_container_width=True):
                st.session_state.page = "register"
                st.rerun()
        with cols[1]:
            if st.button("Forgot Password", use_container_width=True):
                st.warning("Contact system administrator")

def public_dashboard():
    st.sidebar.title(f"👋 Welcome, {st.session_state.username}")
    menu = st.sidebar.radio("Menu", ["Search Crimes", "File Complaint", "My Complaints"])
    
    if menu == "Search Crimes":
        st.header("🔍 Search Crime Records")
        search_term = st.text_input("Search by location or crime type")
        
        if st.button("Search"):
            results = crimes_col.find({
                "$or": [
                    {"location": {"$regex": search_term, "$options": "i"}},
                    {"crime_type": {"$regex": search_term, "$options": "i"}}
                ]
            }).limit(50)
            
            df = pd.DataFrame(list(results))
            if not df.empty:
                st.dataframe(df[["crime_type", "location", "date", "status"]], hide_index=True)
            else:
                st.warning("No matching records found")
    
    elif menu == "File Complaint":
        st.header("📝 File New Complaint")
        with st.form("complaint_form"):
            title = st.text_input("Complaint Title*", max_chars=100)
            description = st.text_area("Description*")
            location = st.text_input("Location*")
            incident_date = st.date_input("Incident Date*", format="DD/MM/YYYY")
            
            if st.form_submit_button("Submit", type="primary"):
                if not all([title, description, location]):
                    st.error("Please fill all required fields (*)")
                else:
                    new_complaint = {
                        "complaint_id": get_next_id(complaints_col, "complaint_id"),
                        "title": title,
                        "description": description,
                        "location": location,
                        "date": datetime.combine(incident_date, datetime.min.time()),
                        "status": "pending",
                        "filed_by": st.session_state.username,
                        "created_at": datetime.now()
                    }
                    complaints_col.insert_one(new_complaint)
                    st.success("Complaint submitted successfully!")
    
    elif menu == "My Complaints":
        st.header("📋 My Complaints")
        my_complaints = list(complaints_col.find({"filed_by": st.session_state.username}))
        
        if my_complaints:
            df = pd.DataFrame(my_complaints)
            st.dataframe(df[["title", "status", "date", "location"]], hide_index=True)
        else:
            st.info("You haven't filed any complaints yet")
    
    if st.sidebar.button("🚪 Logout"):
        logout()
        st.rerun()

def admin_dashboard():
    st.sidebar.title(f"👨‍💻 Admin Dashboard")
    menu = st.sidebar.radio("Menu", ["User Management", "Approve Requests", "System Analytics"])
    
    if menu == "User Management":
        st.header("👥 User Accounts")
        users = list(users_col.find({}, {"password": 0}))
        st.dataframe(pd.DataFrame(users), hide_index=True)
    
    elif menu == "Approve Requests":
        st.header("🛂 Pending Approvals")
        pending = list(access_requests_col.find({"status": "pending"}))
        
        if pending:
            for req in pending:
                with st.expander(f"Request from {req['username']}"):
                    st.write(f"Requested at: {req['requested_at'].strftime('%Y-%m-%d %H:%M')}")
                    if st.button("Approve", key=f"approve_{req['_id']}"):
                        users_col.insert_one({
                            "username": req["username"],
                            "password": req["password"],
                            "type": "department",
                            "created_at": datetime.now()
                        })
                        access_requests_col.update_one(
                            {"_id": req["_id"]},
                            {"$set": {"status": "approved"}}
                        )
                        st.success(f"Approved {req['username']}")
                        st.rerun()
        else:
            st.info("No pending requests")
    
    elif menu == "System Analytics":
        st.header("📊 System Statistics")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Users", users_col.count_documents({}))
        with col2:
            st.metric("Active Crimes", crimes_col.count_documents({"status": "active"}))
        with col3:
            st.metric("Pending Complaints", complaints_col.count_documents({"status": "pending"}))
    
    if st.sidebar.button("🚪 Logout"):
        logout()
        st.rerun()

# Main app router
def main():
    if st.session_state.page == "login":
        login_page()
    elif st.session_state.user_type == "public":
        public_dashboard()
    elif st.session_state.user_type == "admin":
        admin_dashboard()
    else:
        st.warning("Unauthorized access")
        logout()
        st.rerun()

if __name__ == "__main__":
    main()
