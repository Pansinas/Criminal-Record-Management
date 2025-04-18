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
    session_defaults = {
        "user_type": None,
        "email": None,
        "login_attempts": 0,
        "page": "login",
        "last_login_attempt": None,
        "user_data": None
    }
    for key, value in session_defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()

# Database Connection Manager
class DatabaseManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.init_db()
        return cls._instance

    def init_db(self):
        max_retries = 3
        retry_count = 0
        while retry_count < max_retries:
            try:
                # Try cloud MongoDB first
                self.client = MongoClient(
                    os.getenv("MONGO_URI"),
                    serverSelectionTimeoutMS=5000,
                    socketTimeoutMS=30000,
                    connectTimeoutMS=10000
                )
                self.client.server_info()
                self.db = self.client["crime_record_db"]
                st.success("Connected to cloud database successfully")
                return
            except Exception as e:
                retry_count += 1
                if retry_count < max_retries:
                    st.warning(f"Connection attempt {retry_count} failed. Retrying...")
                    time.sleep(2)
                else:
                    try:
                        # Fallback to local MongoDB
                        st.warning("Cloud connection failed. Attempting local connection...")
                        self.client = MongoClient('mongodb://localhost:27017/')
                        self.client.server_info()
                        self.db = self.client["crime_record_db"]
                        st.success("Connected to local database successfully")
                        return
                    except Exception as local_e:
                        st.error("All connection attempts failed. Please check your database configuration.")
                        st.error(f"Cloud Error: {str(e)}")
                        st.error(f"Local Error: {str(local_e)}")
                        st.stop()

    def get_collection(self, name):
        return self.db[name]

# Initialize database connection
db_manager = DatabaseManager()
users_col = db_manager.get_collection("users")
crimes_col = db_manager.get_collection("crimes")
complaints_col = db_manager.get_collection("complaints")
access_requests_col = db_manager.get_collection("access_requests")

# Validation Service
class ValidationService:
    @staticmethod
    def email(email):
        return re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email)

    @staticmethod
    def aadhar(number):
        return re.match(r"^\d{12}$", number)

    @staticmethod
    def phone(number):
        return re.match(r"^\d{10}$", number)

    @staticmethod
    def police_id(id):
        return re.match(r"^[A-Z]{2}\d{3}$", id)

    @staticmethod
    def password(password):
        return len(password) >= 8

# ID Generator
class IDGenerator:
    @staticmethod
    def get_next(collection, id_field):
        last_doc = collection.find_one(sort=[(id_field, -1)])
        return last_doc[id_field] + 1 if last_doc and id_field in last_doc else 1

# Authentication Service
class AuthService:
    MAX_LOGIN_ATTEMPTS = 3
    LOCKOUT_TIME = timedelta(minutes=5)

    @classmethod
    def login(cls, email, password, user_type, police_id=None):
        if cls._is_locked_out():
            st.warning("Too many failed attempts. Try again later.")
            return False

        if user_type == "admin":
            if cls._authenticate_admin(email, password):
                cls._reset_login_attempts()
                return True

        query = {"email": email, "type": user_type}
        if user_type == "department" and not police_id:
            return False
        elif user_type == "department":
            query["police_id"] = police_id

        user = users_col.find_one(query)
        if user and check_password_hash(user["password"], password):
            st.session_state.user_data = user  # Store user details
            cls._reset_login_attempts()
            return True

        cls._increment_login_attempts()
        return False

    # Default admin credentials (for development/testing)
    DEFAULT_ADMIN_EMAIL = "admin123@gmail.com"
    DEFAULT_ADMIN_PASSWORD = "Admin@123"

    @classmethod
    def _authenticate_admin(cls, email, password):
        # Try environment variables first
        env_email = os.getenv("ADMIN_EMAIL")
        env_password = os.getenv("ADMIN_PASSWORD")
        
        # Check environment variables first
        if env_email and env_password:
            if email == env_email and password == env_password:
                return True
        
        # Fall back to default credentials
        if email == cls.DEFAULT_ADMIN_EMAIL and password == cls.DEFAULT_ADMIN_PASSWORD:
            return True
        
        return False

    @classmethod
    def _is_locked_out(cls):
        if st.session_state.login_attempts >= cls.MAX_LOGIN_ATTEMPTS:
            if st.session_state.last_login_attempt:
                time_since = datetime.now() - st.session_state.last_login_attempt
                return time_since < cls.LOCKOUT_TIME
        return False

    @classmethod
    def _increment_login_attempts(cls):
        st.session_state.login_attempts += 1
        st.session_state.last_login_attempt = datetime.now()

    @classmethod
    def _reset_login_attempts(cls):
        st.session_state.login_attempts = 0

    @staticmethod
    def register(user_data):
        if users_col.find_one({"email": user_data["email"]}):
            return False, "Email already registered"
        
        if not ValidationService.email(user_data["email"]):
            return False, "Invalid email format"
        
        if not ValidationService.aadhar(user_data["aadhar"]):
            return False, "Invalid Aadhar number (must be 12 digits)"

        user_data["password"] = generate_password_hash(user_data["password"])
        user_data["created_at"] = datetime.now()
        
        users_col.insert_one(user_data)
        return True, "Registration successful"

# UI Components
class LoginPage:
    def render(self):
        st.title("🔒 Professional Crime Records Management")

        with st.container(border=True):
            login_type = st.selectbox("Login as", ["public", "department", "admin"])
            email = st.text_input("Official Email")
            password = st.text_input("Password", type="password")
            police_id = st.text_input("Police ID") if login_type == "department" else None

            if st.button("Login", type="primary"):
                if not ValidationService.email(email):
                    st.error("Invalid email format")
                    return
                
                if login_type == "department" and not ValidationService.police_id(police_id):
                    st.error("Invalid Police ID format (e.g., TN123)")
                    return
                
                if AuthService.login(email, password, login_type, police_id):
                    st.session_state.update({
                        "email": email,
                        "user_type": login_type,
                        "page": "dashboard"
                    })
                    st.rerun()
                else:
                    st.error("Invalid credentials")

            cols = st.columns(2)
            with cols[0]:
                if st.button("Register New Account"):
                    st.session_state.page = "register"
                    st.rerun()
            with cols[1]:
                if st.button("Reset Password"):
                    st.warning("Contact system administrator")

class RegistrationPage:
    def render(self):
        st.title("📝 New User Registration")
        
        with st.form("registration_form"):
            cols = st.columns(2)
            with cols[0]:
                full_name = st.text_input("Full Name*")
                aadhar = st.text_input("Aadhar Number*")
            with cols[1]:
                email = st.text_input("Official Email*")
                phone = st.text_input("Contact Number")
            
            password = st.text_input("Create Password*", type="password")
            user_type = st.selectbox("Account Type*", ["public", "department"])
            if user_type == "department":
                police_id = st.text_input("Police ID* (e.g., TN123)")
            else:
                police_id = None
            
            if st.form_submit_button("Complete Registration"):
                errors = []
                if not full_name: errors.append("Full name is required")
                if not ValidationService.email(email): errors.append("Invalid email format")
                if not ValidationService.aadhar(aadhar): errors.append("Invalid Aadhar number")
                if not ValidationService.password(password): errors.append("Password must be 8+ characters")
                if user_type == "department":
                    if not police_id: errors.append("Police ID is required")
                    elif not ValidationService.police_id(police_id): errors.append("Invalid Police ID format (e.g., TN123)")
                
                if errors:
                    for error in errors: st.error(error)
                else:
                    user_data = {
                        "full_name": full_name,
                        "email": email,
                        "aadhar": aadhar,
                        "phone": phone,
                        "password": password,
                        "type": user_type,
                        "police_id": police_id if user_type == "department" else None
                    }
                    success, message = AuthService.register(user_data)
                    if success:
                        st.success(message)
                        st.session_state.page = "login"
                        st.rerun()
                    else:
                        st.error(message)

class PublicDashboard:
    def render(self):
        st.sidebar.title(f"👤 {st.session_state.user_data['full_name']}")
        menu = st.sidebar.radio("Menu", [
            "File Complaint", 
            "My Complaints",
            "My Profile"
        ])

        if menu == "File Complaint":
            self._render_complaint_form()
        elif menu == "My Complaints":
            self._render_my_complaints()
        elif menu == "My Profile":
            self._render_profile()

        if st.sidebar.button("🚪 Logout"):
            logout()
            st.rerun()

    def _render_complaint_form(self):
        st.header("📄 File New Complaint Report")
        with st.form("complaint_form", clear_on_submit=True):
            st.subheader("Personal Details")
            st.info(f"""
            Name: {st.session_state.user_data['full_name']}
            Aadhar: {st.session_state.user_data['aadhar']}
            Contact: {st.session_state.user_data.get('phone', 'N/A')}
            """)
            
            st.subheader("Incident Details")
            crime_type = st.selectbox("Crime Type*", [
                "Theft", "Assault", "Fraud", 
                "Cyber Crime", "Property Dispute"
            ])
            incident_date = st.date_input("Date of Incident*")
            location = st.text_input("Location*")
            description = st.text_area("Detailed Description*")
            
            if st.form_submit_button("Submit Official Complaint"):
                complaint_data = {
                    "complaint_id": IDGenerator.get_next(complaints_col, "complaint_id"),
                    "full_name": st.session_state.user_data['full_name'],
                    "aadhar": st.session_state.user_data['aadhar'],
                    "email": st.session_state.email,
                    "crime_type": crime_type,
                    "incident_date": datetime.combine(incident_date, datetime.min.time()),
                    "location": location,
                    "description": description,
                    "status": "pending",
                    "filed_at": datetime.now()
                }
                complaints_col.insert_one(complaint_data)
                st.success("Complaint registered successfully")

    def _render_my_complaints(self):
        st.header("📑 My Registered Complaints")
        complaints = list(complaints_col.find({"email": st.session_state.email}).sort("filed_at", -1))
        if complaints:
            # Display complaints in expandable sections for better readability
            for complaint in complaints:
                with st.expander(f"Complaint #{complaint['complaint_id']} - {complaint['crime_type']} ({complaint['status'].upper()})"): 
                    st.write(f"**Date**: {complaint['incident_date'].strftime('%Y-%m-%d')}")
                    st.write(f"**Location**: {complaint['location']}")
                    st.write(f"**Description**: {complaint['description']}")
                    st.write(f"**Current Status**: {complaint['status'].upper()}")
                    st.write(f"**Filed On**: {complaint['filed_at'].strftime('%Y-%m-%d %H:%M')}")
                    st.divider()
        else:
            st.info("No complaints found in your account")

    def _render_profile(self):
        st.header("📋 Official Profile")
        user = st.session_state.user_data
        with st.form("profile_form"):
            cols = st.columns(2)
            with cols[0]:
                st.text_input("Full Name", value=user['full_name'], disabled=True)
                st.text_input("Aadhar Number", value=user['aadhar'], disabled=True)
            with cols[1]:
                st.text_input("Email", value=st.session_state.email, disabled=True)
                new_phone = st.text_input("Update Contact", value=user.get('phone', ''))
            
            if st.form_submit_button("Update Contact Details"):
                if not ValidationService.phone(new_phone):
                    st.error("Invalid phone number format")
                else:
                    users_col.update_one(
                        {"email": st.session_state.email},
                        {"$set": {"phone": new_phone}}
                    )
                    st.session_state.user_data['phone'] = new_phone
                    st.rerun()

class DepartmentDashboard:
    def render(self):
        st.sidebar.title(f"👮 Department Dashboard")
        menu = st.sidebar.radio("Menu", [
            "Case Management",
            "Review Complaints",
            "My Profile"
        ])

        if menu == "Case Management":
            self._render_case_management()
        elif menu == "Review Complaints":
            self._render_complaints_review()
        elif menu == "My Profile":
            self._render_profile()

        if st.sidebar.button("🚪 Logout"):
            logout()
            st.rerun()

    def _render_case_management(self):
        st.header("📂 Case Management")
        with st.form("case_form"):
            crime_type = st.selectbox("Crime Type*", [
                "Theft", "Assault", "Fraud", 
                "Cyber Crime", "Property Dispute"
            ])
            incident_date = st.date_input("Date of Incident*")
            location = st.text_input("Location*")
            description = st.text_area("Case Details*")
            status = st.selectbox("Status*", ["Open", "Under Investigation", "Closed"])
            
            if st.form_submit_button("Register Case"):
                case_data = {
                    "crime_id": IDGenerator.get_next(crimes_col, "crime_id"),
                    "crime_type": crime_type,
                    "incident_date": datetime.combine(incident_date, datetime.min.time()),
                    "location": location,
                    "description": description,
                    "status": status,
                    "registered_by": st.session_state.email,
                    "registered_at": datetime.now()
                }
                crimes_col.insert_one(case_data)
                st.success("Case registered successfully")

    def _render_complaints_review(self):
        st.header("📑 Review Complaints")
        
        # Filter controls
        col1, col2, col3 = st.columns(3)
        with col1:
            status_filter = st.multiselect("Filter by Status", ["pending", "under_review", "approved", "rejected"], default=["pending"])
        with col2:
            crime_type_filter = st.multiselect("Filter by Crime Type", ["Theft", "Assault", "Fraud", "Cyber Crime", "Property Dispute"])
        with col3:
            date_range = st.date_input("Date Range", value=[datetime.now() - timedelta(days=30), datetime.now()])
        
        # Build query
        query = {}
        if status_filter:
            query["status"] = {"$in": status_filter}
        if crime_type_filter:
            query["crime_type"] = {"$in": crime_type_filter}
        if len(date_range) == 2:
            query["filed_at"] = {
                "$gte": datetime.combine(date_range[0], datetime.min.time()),
                "$lte": datetime.combine(date_range[1], datetime.max.time())
            }
            
        # Fetch all complaints with optional filters
        complaints = list(complaints_col.find(query).sort("filed_at", -1))
        
        if complaints:
            for complaint in complaints:
                with st.expander(f"Complaint #{complaint['complaint_id']} - {complaint['crime_type']} ({complaint['status'].upper()})"):
                    st.write(f"**Complainant**: {complaint['full_name']}")
                    st.write(f"**Date**: {complaint['incident_date'].strftime('%Y-%m-%d')}")
                    st.write(f"**Location**: {complaint['location']}")
                    st.write(f"**Description**: {complaint['description']}")
                    st.write(f"**Current Status**: {complaint['status'].upper()}")
                    st.write(f"**Filed On**: {complaint['filed_at'].strftime('%Y-%m-%d %H:%M')}")
                    
                    status = st.selectbox(
                        "Update Status",
                        ["pending", "under_review", "approved", "rejected"],
                        index=["pending", "under_review", "approved", "rejected"].index(complaint['status']),
                        key=f"status_{complaint['complaint_id']}"
                    )
                    
                    if st.button("Update", key=f"update_{complaint['complaint_id']}"):
                        complaints_col.update_one(
                            {"complaint_id": complaint['complaint_id']},
                            {"$set": {"status": status}}
                        )
                        st.success("Status updated successfully")
                        st.rerun()
        else:
            st.info("No complaints found matching the selected filters")

    def _render_profile(self):
        st.header("👮 Department Profile")
        user = st.session_state.user_data
        with st.form("profile_form"):
            cols = st.columns(2)
            with cols[0]:
                st.text_input("Full Name", value=user['full_name'], disabled=True)
                st.text_input("Aadhar Number", value=user['aadhar'], disabled=True)
            with cols[1]:
                st.text_input("Email", value=st.session_state.email, disabled=True)
                new_phone = st.text_input("Update Contact", value=user.get('phone', ''))
            
            if st.form_submit_button("Update Contact Details"):
                if not ValidationService.phone(new_phone):
                    st.error("Invalid phone number format")
                else:
                    users_col.update_one(
                        {"email": st.session_state.email},
                        {"$set": {"phone": new_phone}}
                    )
                    st.session_state.user_data['phone'] = new_phone
                    st.rerun()

class AdminDashboard:
    def render(self):
        st.sidebar.title(f"👨⚖️ Admin Dashboard")
        menu = st.sidebar.radio("Menu", [
            "Case Management",
            "User Verification",
            "Analytics Hub",
            "System Config"
        ])

        if menu == "Case Management":
            self._render_case_management()
        elif menu == "User Verification":
            self._render_user_verification()
        elif menu == "Analytics Hub":
            self._render_analytics()
        elif menu == "System Config":
            self._render_system_config()
        
        if st.sidebar.button("🚪 Logout"):
            logout()
            st.rerun()

    def _render_system_config(self):
        st.header("⚙️ System Configuration")
        
        # Database Stats
        st.subheader("Database Statistics")
        stats_cols = st.columns(4)
        with stats_cols[0]:
            st.metric("Total Users", users_col.count_documents({}))
        with stats_cols[1]:
            st.metric("Total Cases", crimes_col.count_documents({}))
        with stats_cols[2]:
            st.metric("Total Complaints", complaints_col.count_documents({}))
        with stats_cols[3]:
            st.metric("Pending Verifications", users_col.count_documents({"verified": {"$exists": False}}))
        
        # System Settings
        st.subheader("System Settings")
        with st.form("system_settings"):
            cols = st.columns(2)
            with cols[0]:
                max_login_attempts = st.number_input(
                    "Max Login Attempts",
                    min_value=1,
                    max_value=10,
                    value=AuthService.MAX_LOGIN_ATTEMPTS
                )
            with cols[1]:
                lockout_minutes = st.number_input(
                    "Account Lockout Duration (minutes)",
                    min_value=1,
                    max_value=60,
                    value=int(AuthService.LOCKOUT_TIME.total_seconds() / 60)
                )
            
            if st.form_submit_button("Update Settings"):
                AuthService.MAX_LOGIN_ATTEMPTS = max_login_attempts
                AuthService.LOCKOUT_TIME = timedelta(minutes=lockout_minutes)
                st.success("Settings updated successfully")
        
        # Data Management
        st.subheader("Data Management")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Export All Data"):
                # Create DataFrames
                users_df = pd.DataFrame(list(users_col.find({}, {"password": 0})))
                cases_df = pd.DataFrame(list(crimes_col.find()))
                complaints_df = pd.DataFrame(list(complaints_col.find()))
                
                # Convert to CSV
                users_df.to_csv("users_export.csv", index=False)
                cases_df.to_csv("cases_export.csv", index=False)
                complaints_df.to_csv("complaints_export.csv", index=False)
                
                st.success("Data exported successfully")
        
        with col2:
            if st.button("Clear System Logs"):
                st.warning("This action cannot be undone")
                if st.button("Confirm Clear Logs"):
                    # Add log clearing logic here
                    st.success("System logs cleared successfully")

    def _render_case_management(self):
        st.header("📂 Case Management System")
        
        # Tab selection
        tab1, tab2 = st.tabs(["Cases", "Public Complaints"])
        
        with tab1:
            # Filter controls for cases
            col1, col2 = st.columns(2)
            with col1:
                status_filter = st.multiselect("Filter by Status", ["Open", "Under Investigation", "Closed"])
            with col2:
                crime_type_filter = st.multiselect("Filter by Crime Type", ["Theft", "Assault", "Fraud", "Cyber Crime", "Property Dispute"])
            
            # Build query for cases
            query = {}
            if status_filter:
                query["status"] = {"$in": status_filter}
            if crime_type_filter:
                query["crime_type"] = {"$in": crime_type_filter}
                
            # Fetch and display cases
            cases = list(crimes_col.find(query).sort("registered_at", -1))
            if cases:
                df = pd.DataFrame(cases)
                df["registered_at"] = pd.to_datetime(df["registered_at"]).dt.strftime("%Y-%m-%d %H:%M")
                df = df.drop(columns=["_id"])
                st.dataframe(df, hide_index=True)
                
                # Case details and updates
                for case in cases:
                    with st.expander(f"Case #{case['crime_id']} - {case['crime_type']}"):
                        cols = st.columns([2,1])
                        with cols[0]:
                            st.write(f"**Location:** {case['location']}")
                            st.write(f"**Description:** {case['description']}")
                            st.write(f"**Registered by:** {case['registered_by']}")
                        with cols[1]:
                            new_status = st.selectbox(
                                "Update Status",
                                ["Open", "Under Investigation", "Closed"],
                                index=["Open", "Under Investigation", "Closed"].index(case['status']),
                                key=f"status_{case['crime_id']}"
                            )
                            if st.button("Update Status", key=f"update_{case['crime_id']}"):
                                crimes_col.update_one(
                                    {"crime_id": case['crime_id']},
                                    {"$set": {"status": new_status}}
                                )
                                st.success("Status updated successfully")
                                st.rerun()
            else:
                st.info("No cases found matching the filters")
        
        with tab2:
            # Filter controls for complaints
            status_filter = st.multiselect(
                "Filter by Status",
                ["pending", "under_review", "approved", "rejected"],
                default=["pending"]
            )
            
            # Build query for complaints
            query = {}
            if status_filter:
                query["status"] = {"$in": status_filter}
                
            # Fetch complaints
            complaints = list(complaints_col.find(query).sort("filed_at", -1))
            
            if complaints:
                for complaint in complaints:
                    with st.expander(f"Complaint #{complaint['complaint_id']} - {complaint['crime_type']} ({complaint['status'].upper()})"):
                        st.write(f"**Complainant**: {complaint['full_name']}")
                        st.write(f"**Date**: {complaint['incident_date'].strftime('%Y-%m-%d')}")
                        st.write(f"**Location**: {complaint['location']}")
                        st.write(f"**Description**: {complaint['description']}")
                        st.write(f"**Current Status**: {complaint['status'].upper()}")
                        st.write(f"**Filed On**: {complaint['filed_at'].strftime('%Y-%m-%d %H:%M')}")
                        
                        status = st.selectbox(
                            "Update Status",
                            ["pending", "under_review", "approved", "rejected"],
                            index=["pending", "under_review", "approved", "rejected"].index(complaint['status']),
                            key=f"status_{complaint['complaint_id']}"
                        )
                        
                        if st.button("Update", key=f"update_{complaint['complaint_id']}"):
                            complaints_col.update_one(
                                {"complaint_id": complaint['complaint_id']},
                                {"$set": {"status": status}}
                            )
                            st.success("Status updated successfully")
                            st.rerun()
            else:
                st.info("No complaints found matching the filters")

    def _render_user_verification(self):
        st.header("🕵️ User Verification Portal")
        pending = list(users_col.find({"verified": {"$exists": False}}))
        
        if pending:
            for user in pending:
                with st.expander(f"Verification for {user['full_name']}"):
                    cols = st.columns([2,1])
                    with cols[0]:
                        st.write(f"Email: {user['email']}")
                        st.write(f"Aadhar: {user['aadhar']}")
                        st.write(f"Registered: {user['created_at'].strftime('%Y-%m-%d')}")
                    with cols[1]:
                        if st.button("Verify", key=f"verify_{user['_id']}"):
                            users_col.update_one(
                                {"_id": user["_id"]},
                                {"$set": {"verified": True}}
                            )
                            st.rerun()
        else:
            st.info("No pending verifications")

    def _render_analytics(self):
        st.header("📊 Crime Analytics Dashboard")
        
        # Time period selector
        col1, col2 = st.columns(2)
        with col1:
            period = st.selectbox("Time Period", ["Last 7 Days", "Last 30 Days", "Last 90 Days", "All Time"])
        with col2:
            data_type = st.selectbox("Data Type", ["All", "Cases", "Complaints"])
        
        # Calculate date range
        end_date = datetime.now()
        if period == "Last 7 Days":
            start_date = end_date - timedelta(days=7)
        elif period == "Last 30 Days":
            start_date = end_date - timedelta(days=30)
        elif period == "Last 90 Days":
            start_date = end_date - timedelta(days=90)
        else:
            start_date = datetime.min
        
        # Fetch data based on selection
        cases_query = {"registered_at": {"$gte": start_date, "$lte": end_date}}
        complaints_query = {"filed_at": {"$gte": start_date, "$lte": end_date}}
        
        cases = list(crimes_col.find(cases_query)) if data_type in ["All", "Cases"] else []
        complaints = list(complaints_col.find(complaints_query)) if data_type in ["All", "Complaints"] else []
        
        if cases or complaints:
            # Overview metrics
            metrics = st.columns(4)
            with metrics[0]:
                st.metric("Total Cases", len(cases))
            with metrics[1]:
                st.metric("Total Complaints", len(complaints))
            with metrics[2]:
                open_cases = sum(1 for case in cases if case['status'] == 'Open')
                st.metric("Open Cases", open_cases)
            with metrics[3]:
                pending_complaints = sum(1 for complaint in complaints if complaint['status'] == 'pending')
                st.metric("Pending Complaints", pending_complaints)
            
            # Cases Analysis
            if cases and data_type in ["All", "Cases"]:
                st.subheader("Cases Analysis")
                cases_df = pd.DataFrame(cases)
                
                # Crime type distribution
                col1, col2 = st.columns(2)
                with col1:
                    crime_counts = cases_df['crime_type'].value_counts().reset_index()
                    crime_counts.columns = ['Crime Type', 'Count']
                    fig = px.pie(crime_counts, values='Count', names='Crime Type', 
                                title='Crime Type Distribution', hole=0.3)
                    st.plotly_chart(fig)
                
                # Case status distribution
                with col2:
                    status_counts = cases_df['status'].value_counts().reset_index()
                    status_counts.columns = ['Status', 'Count']
                    fig = px.bar(status_counts, x='Status', y='Count',
                                title='Case Status Distribution')
                    st.plotly_chart(fig)
                
                # Cases timeline
                cases_df['registered_at'] = pd.to_datetime(cases_df['registered_at'])
                timeline_df = cases_df.groupby(['registered_at', 'status']).size().reset_index(name='count')
                fig = px.line(timeline_df, x='registered_at', y='count', color='status',
                             title='Cases Timeline')
                st.plotly_chart(fig)
            
            # Complaints Analysis
            if complaints and data_type in ["All", "Complaints"]:
                st.subheader("Complaints Analysis")
                complaints_df = pd.DataFrame(complaints)
                
                # Complaint type distribution
                col1, col2 = st.columns(2)
                with col1:
                    complaint_counts = complaints_df['crime_type'].value_counts().reset_index()
                    complaint_counts.columns = ['Crime Type', 'Count']
                    fig = px.pie(complaint_counts, values='Count', names='Crime Type',
                                title='Complaint Type Distribution', hole=0.3)
                    st.plotly_chart(fig)
                
                # Complaint status distribution
                with col2:
                    status_counts = complaints_df['status'].value_counts().reset_index()
                    status_counts.columns = ['Status', 'Count']
                    fig = px.bar(status_counts, x='Status', y='Count',
                                title='Complaint Status Distribution')
                    st.plotly_chart(fig)
                
                # Complaints timeline
                complaints_df['filed_at'] = pd.to_datetime(complaints_df['filed_at'])
                timeline_df = complaints_df.groupby(['filed_at', 'status']).size().reset_index(name='count')
                fig = px.line(timeline_df, x='filed_at', y='count', color='status',
                             title='Complaints Timeline')
                st.plotly_chart(fig)
        else:
            st.info("No data available for the selected time period and data type")

# Main Application
def logout():
    st.session_state.update({
        "user_type": None,
        "email": None,
        "user_data": None,
        "page": "login"
    })

def main():
    if st.session_state.page == "login":
        LoginPage().render()
    elif st.session_state.page == "register":
        RegistrationPage().render()
    elif st.session_state.user_type == "public":
        PublicDashboard().render()
    elif st.session_state.user_type == "department":
        DepartmentDashboard().render()
    elif st.session_state.user_type == "admin":
        AdminDashboard().render()
    else:
        st.warning("Authentication Required")
        logout()
        st.rerun()

if __name__ == "__main__":
    main()
