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

init_session_state()

# Secure MongoDB Atlas connection
try:
    MONGODB_URI = os.getenv("MONGODB_URI")
    
    if not MONGODB_URI:
        st.error("MongoDB connection string not configured in environment variables")
        st.stop()

    client = MongoClient(
        MONGODB_URI,
        serverSelectionTimeoutMS=5000,
        socketTimeoutMS=30000,
        connectTimeoutMS=30000,
        retryWrites=True,
        retryReads=True,
        appName="CrimeRecordSystem-v1"
    )
    
    # Test connection
    client.admin.command('ping')
    db = client.get_database("crime_record_db")
    
    # Initialize collections
    users_col = db.users
    crimes_col = db.crimes
    complaints_col = db.complaints
    access_requests_col = db.access_requests
    
except Exception as e:
    st.error(f"Database connection failed: {str(e)}")
    st.error("Troubleshooting steps:")
    st.error("1. Verify MONGODB_URI in .env/Render config")
    st.error("2. Check Atlas IP whitelist and credentials")
    st.error("3. Ensure database exists in Atlas")
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
    st.sidebar.write(f"Welcome, {st.session_state.username}")
    menu = st.sidebar.selectbox("Menu", ["Search Crimes", "File Complaint", "My Complaints", "Logout"])
    
    if menu == "Search Crimes":
        st.header("🔎 Search Crimes")
        search_option = st.radio("Search by", ["Crime ID", "Location", "Date Range"])
        
        if search_option == "Crime ID":
            cid = st.number_input("Enter Crime ID", min_value=1)
            if st.button("Search"):
                crime = crimes_col.find_one({"crime_id": cid})
                if crime:
                    st.json(crime)
                else:
                    st.warning("Crime not found")
        
        elif search_option == "Location":
            location = st.text_input("Enter Location")
            if st.button("Search"):
                crimes = list(crimes_col.find({"location": {"$regex": location, "$options": "i"}}))
                st.write(pd.DataFrame(crimes))
        
        elif search_option == "Date Range":
            col1, col2 = st.columns(2)
            with col1:
                start_date = st.date_input("Start Date")
            with col2:
                end_date = st.date_input("End Date")
            
            if st.button("Search"):
                crimes = list(crimes_col.find({
                    "date": {
                        "$gte": datetime.combine(start_date, datetime.min.time()),
                        "$lte": datetime.combine(end_date, datetime.max.time())
                    }
                }))
                st.write(pd.DataFrame(crimes))
    
    elif menu == "File Complaint":
        st.header("📝 File Complaint")
        with st.form("complaint_form"):
            name = st.text_input("Your Name")
            description = st.text_area("Complaint Details")
            location = st.text_input("Location")
            date = st.date_input("Incident Date")
            
            if st.form_submit_button("Submit"):
                complaint_id = get_next_id(complaints_col, "complaint_id")
                complaints_col.insert_one({
                    "complaint_id": complaint_id,
                    "username": st.session_state.username,
                    "name": name,
                    "description": description,
                    "location": location,
                    "date": datetime.combine(date, datetime.min.time()),
                    "status": "Pending",
                    "created_at": datetime.now()
                })
                st.success("Complaint filed successfully!")
    
    elif menu == "My Complaints":
        st.header("📋 My Complaints")
        complaints = list(complaints_col.find({"username": st.session_state.username}))
        st.write(pd.DataFrame(complaints))
    
    elif menu == "Logout":
        logout()
        st.rerun()

def department_dashboard():
    st.sidebar.title(f"Department Dashboard")
    st.sidebar.write(f"Welcome, {st.session_state.username}")
    menu = st.sidebar.selectbox("Menu", ["Manage Complaints", "Manage Crimes", "Analytics", "Logout"])
    
    if menu == "Manage Complaints":
        st.header("📩 Manage Complaints")
        complaints = list(complaints_col.find())
        
        for complaint in complaints:
            with st.expander(f"Complaint #{complaint['complaint_id']}"):
                st.write(complaint)
                new_status = st.selectbox(
                    "Update Status",
                    ["Pending", "In Progress", "Resolved"],
                    key=f"status_{complaint['_id']}"
                )
                if st.button("Update", key=f"update_{complaint['_id']}"):
                    complaints_col.update_one(
                        {"_id": complaint["_id"]},
                        {"$set": {"status": new_status}}
                    )
                    st.rerun()
    
    elif menu == "Manage Crimes":
        st.header("🔧 Manage Crimes")
        tab1, tab2 = st.tabs(["Add Crime", "View Crimes"])
        
        with tab1:
            with st.form("add_crime"):
                name = st.text_input("Offender Name")
                description = st.text_input("Crime Description")
                location = st.text_input("Location")
                date = st.date_input("Date")
                
                if st.form_submit_button("Add Crime"):
                    crime_id = get_next_id(crimes_col, "crime_id")
                    crimes_col.insert_one({
                        "crime_id": crime_id,
                        "name": name,
                        "description": description,
                        "location": location,
                        "date": datetime.combine(date, datetime.min.time()),
                        "added_by": st.session_state.username,
                        "created_at": datetime.now()
                    })
                    st.success("Crime added successfully!")
        
        with tab2:
            crimes = list(crimes_col.find())
            st.write(pd.DataFrame(crimes))
    
    elif menu == "Analytics":
        st.header("📊 Crime Analytics")
        
        # Crime location distribution
        st.subheader("Crime Locations")
        location_data = list(crimes_col.aggregate([
            {"$group": {"_id": "$location", "count": {"$sum": 1}}}
        ]))
        if location_data:
            df = pd.DataFrame(location_data)
            fig = px.bar(df, x="_id", y="count", title="Crimes by Location")
            st.plotly_chart(fig)
        
        # Complaint status distribution
        st.subheader("Complaint Status")
        status_data = list(complaints_col.aggregate([
            {"$group": {"_id": "$status", "count": {"$sum": 1}}}
        ]))
        if status_data:
            df = pd.DataFrame(status_data)
            fig = px.pie(df, names="_id", values="count", title="Complaint Status Distribution")
            st.plotly_chart(fig)
    
    elif menu == "Logout":
        logout()
        st.rerun()

def admin_dashboard():
    st.sidebar.title(f"Admin Dashboard")
    st.sidebar.write(f"Welcome, {st.session_state.username}")
    menu = st.sidebar.selectbox("Menu", ["Approve Requests", "Manage Users", "System Logs", "Logout"])
    
    if menu == "Approve Requests":
        st.header("🛂 Approve Department Requests")
        requests = list(access_requests_col.find({"status": "pending"}))
        
        if not requests:
            st.info("No pending requests")
        else:
            for req in requests:
                with st.expander(f"Request from {req['username']}"):
                    st.write(f"Requested at: {req['requested_at']}")
                    if st.button(f"Approve {req['username']}", key=f"approve_{req['_id']}"):
                        success, message = approve_department_user(req["_id"])
                        if success:
                            st.success(message)
                            st.rerun()
                        else:
                            st.error(message)
    
    elif menu == "Manage Users":
        st.header("👥 User Management")
        users = list(users_col.find({}, {"password": 0}))
        st.write(pd.DataFrame(users))
    
    elif menu == "System Logs":
        st.header("📜 System Activity")
        st.write("Recent user activity would appear here")
    
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
