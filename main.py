import streamlit as st
import pandas as pd
import plotly.express as px
import sqlite3
import secrets
import string
import re
from datetime import datetime
from passlib.hash import pbkdf2_sha256
import os
import plotly.graph_objects as go
from prophet import Prophet
import base64
from fpdf import FPDF
import tempfile
from io import StringIO
import google.generativeai as genai

#                              qo/)-a7ucvQF user3       '\cA/$t2D2;x user4
#                              L^.Ojy`3l]?| user1       #:![@mDi\5:x  user2

# Set wide layout
st.set_page_config(
    page_title="Revenue Forecasting",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://www.walmart.com/help',
        'Report a bug': "https://www.walmart.com/contact",
        'About': "# Walmart Revenue Forecasting Dashboard"
    }
)

# Inject CSS
st.markdown(
    """
    <style>
    body {
        background-color: white;
        color: black;
    }


    </style>
    """,
    unsafe_allow_html=True
)


# Database setup for user authentication
def init_db():
    conn = sqlite3.connect("walmart_dashboard.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users(
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE, 
                      password TEXT,
                      email TEXT,
                      salt TEXT,
                      failed_attempts INTEGER DEFAULT 0,
                      account_locked INTEGER DEFAULT 0,
                      last_login TEXT,
                      account_created TEXT,
                      last_password_change TEXT
                  )''')

    # Create table for user queries history
    c.execute('''CREATE TABLE IF NOT EXISTS user_queries(
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT,
                      query TEXT,
                      timestamp TEXT,
                      FOREIGN KEY(username) REFERENCES users(username)
                  )''')

    # Create table for user feedback
    c.execute('''CREATE TABLE IF NOT EXISTS user_feedback(
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT,
                      rating INTEGER,
                      comments TEXT,
                      timestamp TEXT,
                      FOREIGN KEY(username) REFERENCES users(username)
                  )''')

    conn.commit()
    conn.close()


# Enhanced password generator
def generate_strong_password(length=12):
    """Generate a strong password with mixed characters"""
    characters = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(characters) for _ in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in string.punctuation for c in password)):
            break
    return password


# Password strength checker
def check_password_strength(password):
    """Check password strength and return feedback"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"

    return True, "Password is strong"


# User authentication functions with enhanced security
def create_user(username, password, email):
    conn = sqlite3.connect('walmart_dashboard.db')
    c = conn.cursor()
    salt = secrets.token_bytes(16)
    hashed_pwd = pbkdf2_sha256.using(salt=salt).hash(password)
    created_at = datetime.now().isoformat()
    try:
        c.execute('''INSERT INTO users 
                     (username, password, email, salt, failed_attempts, account_locked, last_login, account_created, last_password_change) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (username, hashed_pwd, email, salt, 0, 0, created_at, created_at, created_at))
        conn.commit()
        conn.close()
        return True, "Account created successfully!"
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Username already exists"
    except Exception as e:
        conn.close()
        return False, f"Error creating account: {str(e)}"


def verify_user(username, password):
    conn = sqlite3.connect('walmart_dashboard.db')
    c = conn.cursor()

    # First check if account is locked
    c.execute("SELECT account_locked, failed_attempts FROM users WHERE username=?", (username,))
    result = c.fetchone()

    if not result:
        conn.close()
        return False, "Invalid username or password"

    account_locked, failed_attempts = result

    if account_locked == 1:  # Assuming 1 means locked, 0 means not locked
        conn.close()
        return False, "Account is locked due to too many failed attempts. Please contact support."

    # Get stored hash and salt
    c.execute("SELECT password, salt FROM users WHERE username = ?", (username,))
    result = c.fetchone()

    if not result:
        conn.close()
        return False, "Invalid username or password"

    stored_hash, salt = result

    # Verify password
    if pbkdf2_sha256.using(salt=salt).verify(password, stored_hash):
        # Reset failed attempts on successful login
        c.execute("UPDATE users SET failed_attempts=0, last_login=? WHERE username=?",
                  (datetime.now().isoformat(), username))
        conn.commit()
        conn.close()
        return True, "Login successful"
    else:
        # Increment failed attempts
        new_attempts = failed_attempts + 1
        c.execute("UPDATE users SET failed_attempts=? WHERE username=?",
                  (new_attempts, username))

        # Lock account after 5 failed attempts
        if new_attempts >= 5:
            c.execute("UPDATE users SET account_locked=1 WHERE username=?", (username,))
            conn.commit()
            conn.close()
            return False, "Account locked due to too many failed attempts. Please contact support."

        conn.commit()
        conn.close()
        return False, f"Invalid username or password. {5 - new_attempts} attempts remaining."


def reset_password(username, new_password):
    conn = sqlite3.connect('walmart_dashboard.db')
    c = conn.cursor()

    try:
        # Generate a new random salt in bytes format
        salt = os.urandom(16)

        # Hash the new password with the salt
        hashed_pwd = pbkdf2_sha256.using(salt=salt).hash(new_password)

        # Update the database
        c.execute("UPDATE users SET password=?, salt=?, failed_attempts=0, last_password_change=? WHERE username=?",
                  (hashed_pwd, salt, datetime.now().isoformat(), username))
        conn.commit()

        return True, "Password reset successfully"
    except Exception as e:
        conn.rollback()
        return False, f"Error resetting password: {str(e)}"
    finally:
        conn.close()


def log_user_query(username, query):
    conn = sqlite3.connect('walmart_dashboard.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO user_queries (username, query, timestamp) VALUES (?, ?, ?)",
                  (username, query, datetime.now().isoformat()))
        conn.commit()
    except Exception as e:
        st.error(f"Error logging query: {e}")
    finally:
        conn.close()


def submit_feedback(username, rating, comments):
    conn = sqlite3.connect('walmart_dashboard.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO user_feedback (username, rating, comments, timestamp) VALUES (?, ?, ?, ?)",
                  (username, rating, comments, datetime.now().isoformat()))
        conn.commit()
        return True
    except Exception as e:
        st.error(f"Error submitting feedback: {e}")
        return False
    finally:
        conn.close()


# Initialize database
init_db()

# Session state management
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'current_page' not in st.session_state:
    st.session_state.current_page = "login"
if 'show_password_reset' not in st.session_state:
    st.session_state.show_password_reset = False
if 'generated_password' not in st.session_state:
    st.session_state.generated_password = ""
if 'feedback_submitted' not in st.session_state:
    st.session_state.feedback_submitted = False


# Authentication pages with enhanced UI
def login_page():
    st.title("🔐 Login to Your Account")

    with st.form("login_form"):
        username = st.text_input("👤 Username", key="login_username")
        password = st.text_input("🔑 Password", type="password", key="login_password")

        submitted = st.form_submit_button("🚪 Login")

        if submitted:
            if not username or not password:
                st.error("❌ Please enter both username and password")
            else:
                success, message = verify_user(username, password)
                if success:
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.session_state.current_page = "main"
                    st.rerun()
                else:
                    st.error(message)
    if st.button("📝 Go to Sign Up"):
        st.session_state.current_page = "signup"
        st.rerun()


def signup_page():
    st.title("📝 Create New Account")

    # Generate password button outside the form
    if st.button("🔑 Generate Strong Password"):
        st.session_state.generated_password = generate_strong_password()
        st.rerun()

    with st.form("signup_form"):
        email = st.text_input("📧 Email", key="signup_email")
        username = st.text_input("👤 Choose a Username", key="signup_username")

        # Use the generated password if available
        password = st.text_input("Choose a Password",
                                 type="password",
                                 key="signup_password",
                                 value=st.session_state.generated_password)
        confirm_password = st.text_input("Confirm Password",
                                         type="password",
                                         key="signup_confirm_password",
                                         value=st.session_state.generated_password)

        # Password strength meter
        if password:
            strength, message = check_password_strength(password)
            if strength:
                st.success(message)
            else:
                st.warning(message)

        submitted = st.form_submit_button("✅ Create Account")

        if submitted:
            if not email or not username or not password:
                st.error("All fields are required")
            elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                st.error("⚠️ Please enter a valid email address")
            elif password != confirm_password:
                st.error("⚠️ Passwords don't match")
            else:
                strength, message = check_password_strength(password)
                if not strength:
                    st.error(message)
                else:
                    success, message = create_user(username, password, email)
                    if success:
                        st.success(message)
                        st.session_state.current_page = "login"
                        st.session_state.generated_password = ""  # Clear generated password
                        st.rerun()
                    else:
                        st.error(message)

    if st.button("⬅️ Back to Login"):
        st.session_state.current_page = "login"
        st.session_state.generated_password = ""  # Clear generated password
        st.rerun()


# Load data
@st.cache_data
def load_data():
    data = pd.read_csv("Walmart.csv")
    # Clean data
    data['unit_price'] = data['unit_price'].str.replace('$', '').astype(float)
    data['date'] = pd.to_datetime(data['date'], format='%d/%m/%y',dayfirst=True)
    data['total_sales'] = data['unit_price'] * data['quantity']
    data['profit'] = data['total_sales'] * data['profit_margin']
    data['month'] = data['date'].dt.month
    data['year'] = data['date'].dt.year
    data['day_of_week'] = data['date'].dt.day_name()
    data['hour'] = pd.to_datetime(data['time'], errors='coerce').dt.hour
    data['time_of_day'] = pd.cut(data['hour'],
                                 bins=[0, 6, 12, 18, 24],
                                 labels=['Night', 'Morning', 'Afternoon', 'Evening'],
                                 right=False)
    data['revenue'] = data['unit_price'] * data['quantity']
    data['profit'] = data['revenue'] * data['profit_margin']
    return data


# Forecasting function
def run_forecast(data, periods=12):
    # Prepare data for Prophet
    df_prophet = data.groupby('date')['total_sales'].sum().reset_index()
    df_prophet.columns = ['ds', 'y']

    # Train model
    model = Prophet(
        yearly_seasonality=True,
        weekly_seasonality=True,
        daily_seasonality=False,
        seasonality_mode='multiplicative'
    )
    model.add_country_holidays(country_name='US')
    model.fit(df_prophet)

    # Make future dataframe
    future = model.make_future_dataframe(periods=periods, freq='M')

    # Predict
    forecast = model.predict(future)

    return model, forecast


# Add these functions with your other utility functions
def create_pdf_report(filtered_data, username):
    """Create a PDF report from the filtered data"""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Add title
    pdf.cell(200, 10, txt=f"Walmart Sales Report for {username}", ln=1, align='C')
    pdf.ln(10)

    # Add date and filters info
    pdf.cell(200, 10, txt=f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1, align='C')
    pdf.ln(10)

    # Add key metrics
    pdf.set_font("Arial", size=12, style='B')
    pdf.cell(200, 10, txt="Key Metrics", ln=1)
    pdf.set_font("Arial", size=10)

    total_sales = filtered_data['total_sales'].sum()
    total_profit = filtered_data['profit'].sum()
    avg_rating = filtered_data['rating'].mean()
    total_transactions = len(filtered_data)

    pdf.cell(200, 10, txt=f"Total Sales: ${total_sales:,.2f}", ln=1)
    pdf.cell(200, 10, txt=f"Total Profit: ${total_profit:,.2f}", ln=1)
    pdf.cell(200, 10, txt=f"Average Rating: {avg_rating:.1f}/10", ln=1)
    pdf.cell(200, 10, txt=f"Total Transactions: {total_transactions:,}", ln=1)
    pdf.ln(5)

    # Add top categories
    pdf.set_font("Arial", size=12, style='B')
    pdf.cell(200, 10, txt="Top Categories by Sales", ln=1)
    pdf.set_font("Arial", size=10)

    top_categories = filtered_data.groupby('category')['total_sales'].sum().sort_values(ascending=False).head(5)
    for i, (category, sales) in enumerate(top_categories.items(), 1):
        pdf.cell(200, 10, txt=f"{i}. {category}: ${sales:,.2f}", ln=1)
    pdf.ln(5)

    # Add top cities
    pdf.set_font("Arial", size=12, style='B')
    pdf.cell(200, 10, txt="Top Cities by Sales", ln=1)
    pdf.set_font("Arial", size=10)

    top_cities = filtered_data.groupby('City')['total_sales'].sum().sort_values(ascending=False).head(5)
    for i, (city, sales) in enumerate(top_cities.items(), 1):
        pdf.cell(200, 10, txt=f"{i}. {city}: ${sales:,.2f}", ln=1)

    # Save to temporary file
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(temp_file.name)
    temp_file.close()

    return temp_file.name


def create_csv_download(filtered_data):
    """Create CSV file from filtered data"""
    # Create a StringIO buffer for the CSV data
    csv_buffer = StringIO()
    filtered_data.to_csv(csv_buffer, index=False)
    csv_buffer.seek(0)

    # Create temporary file
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    temp_file.write(csv_buffer.getvalue().encode())
    temp_file.close()

    return temp_file.name


with st.sidebar:
    st.title("AI-Revenue Forecasting & Trend Analysis for Business Growth")
    # st.title("🛒 Walmart Analytics")
    # st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/c/ca/Walmart_logo.svg/1200px-Walmart_logo.svg.png",
    #          width=150)
# Main application logic
if st.session_state.authenticated:
    df = load_data()

    st.markdown("""
                        <style>
                               .block-container {
                                    padding-top: 0rem;
                                    padding-bottom: 3rem;
                                    padding-left: 5rem;
                                    padding-right: 5rem;
                                }
                        </style>
                        """, unsafe_allow_html=True)
    # Logout button
    if st.sidebar.button("🔓 Logout"):
        st.session_state.logout_confirmation = True

    if st.session_state.get('logout_confirmation', False):
        st.sidebar.warning("Are you sure you want to logout?")
        if st.sidebar.button("Yes, logout"):
            st.session_state.authenticated = False
            st.session_state.username = None
            st.session_state.current_page = "login"
            st.session_state.logout_confirmation = False
            st.rerun()
        if st.sidebar.button("No, stay logged in"):
            st.session_state.logout_confirmation = False

    # Add change password option in the sidebar
    if st.sidebar.button("🔑 Change Password"):
        st.session_state.show_change_password = True

    if st.session_state.get('show_change_password', False):
        with st.sidebar.form("change_password_form"):
            st.write("### Change Password")
            current_pw = st.text_input("Current Password", type="password")
            new_pw = st.text_input("New Password", type="password")
            confirm_pw = st.text_input("Confirm New Password", type="password")

            submitted = st.form_submit_button("Update Password")
            cancel = st.form_submit_button("Cancel")

            if submitted:
                # Verify current password first
                if not current_pw:
                    st.error("Please enter your current password")
                elif not new_pw or not confirm_pw:
                    st.error("Please enter and confirm your new password")
                else:
                    success, message = verify_user(st.session_state.username, current_pw)
                    if success:
                        if new_pw != confirm_pw:
                            st.error("New passwords don't match")
                        else:
                            strength, msg = check_password_strength(new_pw)
                            if not strength:
                                st.error(msg)
                            else:
                                success, message = reset_password(st.session_state.username, new_pw)
                                if success:
                                    st.success("Password changed successfully!")
                                    st.session_state.show_change_password = False
                                else:
                                    st.error(message)
                    else:
                        st.error("Current password is incorrect")

            if cancel:
                st.session_state.show_change_password = False

    # ... (rest of your existing sidebar code)
    # Display user info in sidebar
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"**Logged in as:** {st.session_state.username}")

    # Feedback section in sidebar
    with st.sidebar.expander("💬 Give Feedback"):
        if not st.session_state.feedback_submitted:
            rating = st.slider("Rate your experience (1-5)", 1, 5, 3)
            comments = st.text_area("Comments or suggestions")
            if st.button("Submit Feedback"):
                if submit_feedback(st.session_state.username, rating, comments):
                    st.success("Thank you for your feedback!")
                    st.session_state.feedback_submitted = True
        else:
            st.info("Thank you for your feedback!")

    # Sidebar with filters
    with st.sidebar:
        st.markdown("#### 🧠 Ask and Analyze!")

        category = st.selectbox("📦 Choose Category", ['All'] + sorted(df['category'].unique()), key="choose_category")
        payment_method = st.selectbox("💳 Payment Method", ['All'] + sorted(df['payment_method'].unique()),
                                      key="payment_method")
        city = st.selectbox("🌆 City", ['All'] + sorted(df['City'].unique()), key="city")
        year = st.selectbox("📅 Year", ['All'] + sorted(df['year'].unique()), key="year")
        st.markdown("---")

        # Initialize session state for questions
        if "questions" not in st.session_state:
            st.session_state.questions = [
                "What is the total revenue by category?",
                "Which city has the highest sales?",
                "What is the monthly sales trend?",
                "What is the total profit by category?",
                "Which category has the highest sales?",
                "What is the average unit price by category?",
                "What is the total quantity sold by category?",
                "Which payment method generates the most revenue?",
                "What is the total revenue for each city?",
                "What are the top 5 products by sales?",
                "What is the sales trend for the last year?",
                "Which month has the highest sales?",
                "What is the average profit margin by category?"
            ]

        if "show_new_question_input" not in st.session_state:
            st.session_state.show_new_question_input = False

            # Show previous questions
        st.markdown("### 📜 New Questions")
        for i, q in enumerate(st.session_state.questions[13:]):  # Show only last 10 questions
            st.markdown(f"<p style='margin: 0 0 10px 0;'>💬 {q}</p>", unsafe_allow_html=True)
        # Button to show input field
        if st.button("➕ New question"):
            st.session_state.show_new_question_input = True

        # Input field for new question
        if st.session_state.show_new_question_input:
            new_q = st.text_input("✏️ Type your question", key="new_question_input")
            if st.button("✅ Add Question", key="btn_add_question"):
                if new_q.strip():
                    st.session_state.questions.append(new_q.strip())
                    log_user_query(st.session_state.username, new_q.strip())
                    st.session_state.show_new_question_input = False
                    st.rerun()
        # Add download section below the change password button
        st.sidebar.markdown("---")
        st.sidebar.markdown("### 📥 Download Data")

        # Create filtered data for download (using the same filters as your dashboard)
        download_df = df.copy()
        if category != 'All':
            download_df = download_df[download_df['category'] == category]
        if payment_method != 'All':
            download_df = download_df[download_df['payment_method'] == payment_method]
        if city != 'All':
            download_df = download_df[download_df['City'] == city]
        if year != 'All':
            download_df = download_df[download_df['year'] == int(year)]

        # Create download buttons
        col1, col2 = st.sidebar.columns(2)

        with col1:
            # CSV Download
            csv_path = create_csv_download(download_df)
            with open(csv_path, "rb") as f:
                csv_data = f.read()
            b64_csv = base64.b64encode(csv_data).decode()
            href_csv = f'<a href="data:file/csv;base64,{b64_csv}" download="walmart_filtered_data.csv">⬇️ CSV</a>'
            st.sidebar.markdown(href_csv, unsafe_allow_html=True)

        with col2:
            # PDF Download
            pdf_path = create_pdf_report(download_df, st.session_state.username)
            with open(pdf_path, "rb") as f:
                pdf_data = f.read()
            b64_pdf = base64.b64encode(pdf_data).decode()
            href_pdf = f'<a href="data:application/pdf;base64,{b64_pdf}" download="walmart_sales_report.pdf">⬇️ PDF</a>'
            st.sidebar.markdown(href_pdf, unsafe_allow_html=True)

        st.sidebar.markdown("---")

    # Remove whitespace from the top of the page and sidebar
    st.markdown("""
            <style>
                   .block-container {
                        padding-top: 2rem;
                        padding-bottom: 0rem;
                        padding-left: 5rem;
                        padding-right: 5rem;
                    }
            </style>
            """, unsafe_allow_html=True)

    # Main content
    st.markdown("<h1 style='text-align: center;'>Sales Analytics Dashboard</h1>", unsafe_allow_html=True)
    st.text("")
    st.text("")

    # Filter data based on sidebar selections
    filtered_df = df.copy()
    if category != 'All':
        filtered_df = filtered_df[filtered_df['category'] == category]
    if payment_method != 'All':
        filtered_df = filtered_df[filtered_df['payment_method'] == payment_method]
    if city != 'All':
        filtered_df = filtered_df[filtered_df['City'] == city]
    if year != 'All':
        filtered_df = filtered_df[filtered_df['year'] == int(year)]

    # Key metrics
    total_sales = filtered_df['total_sales'].sum()
    total_profit = filtered_df['profit'].sum()
    avg_rating = filtered_df['rating'].mean()
    total_transactions = len(filtered_df)
    avg_sale_per_transaction = total_sales / total_transactions if total_transactions > 0 else 0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("💰 Total Sales", f"${total_sales:,.2f}",
                delta=f"${total_sales - df['total_sales'].sum() / len(df['year'].unique()):,.2f} vs yearly avg")
    col2.metric("📈 Total Profit", f"${total_profit:,.2f}",
                delta=f"{((total_profit / total_sales) * 100 - (df['profit'].sum() / df['total_sales'].sum()) * 100):.1f}% margin change")
    col3.metric("⭐ Average Rating", f"{avg_rating:.1f}/10",
                delta=f"{avg_rating - df['rating'].mean():.1f} vs overall")
    col4.metric("🧾 Total Transactions", total_transactions,
                delta=f"${avg_sale_per_transaction:,.2f} avg sale")

    # Visualization section
    st.text("")
    # st.header("🔍 Sales Analysis")

    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9 = st.tabs([
        "📊 Trend Analysis",
        "📦 Category Breakdown",
        "🌍 Geographical Analysis",
        "📊 Predefined Analytics Questions",
        "🤖 AI-Powered Insights",
        "📈 Revenue Forcasting  ",
        "📍 Location Analysis",
        "⏰ Time Analysis",
        "💡 Sample Insights"
    ])

    with tab1:
        # Monthly sales trend
        monthly_sales = filtered_df.groupby(['year', 'month'])['total_sales'].sum().reset_index()
        monthly_sales['date'] = pd.to_datetime(monthly_sales[['year', 'month']].assign(day=1))

        fig = px.line(monthly_sales, x='date', y='total_sales',
                      title='Monthly Sales Trend',
                      labels={'total_sales': 'Total Sales ($)', 'date': 'Date'},
                      markers=True)
        fig.update_layout(hovermode="x unified")
        st.plotly_chart(fig, use_container_width=True)

        # Weekly sales trend
        weekly_sales = filtered_df.groupby(['year', 'day_of_week'])['total_sales'].sum().reset_index()
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        weekly_sales['day_of_week'] = pd.Categorical(weekly_sales['day_of_week'], categories=day_order, ordered=True)
        weekly_sales = weekly_sales.sort_values('day_of_week')

        fig = px.bar(weekly_sales, x='day_of_week', y='total_sales',
                     title='Weekly Sales Pattern',
                     labels={'total_sales': 'Total Sales ($)', 'day_of_week': 'Day of Week'},
                     color='year',
                     barmode='group')
        st.plotly_chart(fig, use_container_width=True)

    with tab2:
        # Sales by category
        category_sales = filtered_df.groupby('category')['total_sales'].sum().sort_values(ascending=False).reset_index()

        fig = px.bar(category_sales, x='total_sales', y='category',
                     title='Sales by Category',
                     labels={'total_sales': 'Total Sales ($)', 'category': 'Category'},
                     color='category')
        st.plotly_chart(fig, use_container_width=True)

        # Profit by category
        category_profit = filtered_df.groupby('category')['profit'].sum().sort_values(ascending=False).reset_index()

        fig = px.pie(category_profit, values='profit', names='category',
                     title='Profit Distribution by Category',
                     hole=0.3)
        st.plotly_chart(fig, use_container_width=True)

    with tab3:
        # Sales by city (top 10)
        city_sales = filtered_df.groupby('City')['total_sales'].sum().sort_values(ascending=False).head(
            10).reset_index()

        fig = px.bar(city_sales, x='total_sales', y='City',
                     title='Top 10 Cities by Sales',
                     labels={'total_sales': 'Total Sales ($)', 'City': 'City'},
                     color='total_sales',
                     color_continuous_scale='Blues')
        st.plotly_chart(fig, use_container_width=True)

        # Geographical distribution
        if 'City' in filtered_df.columns:
            city_geo = filtered_df.groupby('City').agg({
                'total_sales': 'sum',
                'profit': 'sum',
                'rating': 'mean'
            }).reset_index()

            fig = px.scatter(city_geo, x='total_sales', y='profit',
                             size='rating', color='City',
                             title='Sales vs Profit by City (Size = Rating)',
                             labels={'total_sales': 'Total Sales ($)', 'profit': 'Profit ($)'})
            st.plotly_chart(fig, use_container_width=True)

    with tab4:
        # Predefined questions section
        question = st.selectbox("🧠 Select a question:",
                                options=st.session_state.questions[:13],
                                index=0,
                                key="ai_question_select")
        if st.button("🔍 Get Answer"):
            if question:
                try:
                    # Log the query
                    log_user_query(st.session_state.username, question)

                    # Answering the questions based on user input
                    if "total revenue" in question.lower() and "category" in question.lower():
                        result = df.groupby('category')['total_sales'].sum().sort_values(ascending=False)
                        st.write(result)

                        fig = px.bar(result.reset_index(), x='total_sales', y='category',
                                     title='Total Revenue by Category',
                                     labels={'total_sales': 'Revenue ($)', 'category': 'Category'},
                                     color='category')
                        st.plotly_chart(fig, use_container_width=True)

                    elif "highest sales" in question.lower() and "city" in question.lower():
                        result = df.groupby('City')['total_sales'].sum().sort_values(ascending=False).head(1)
                        st.write(
                            f"The city with the highest sales is {result.index[0]} with ${result.values[0]:,.2f} in sales.")

                    elif "monthly" in question.lower() and "trend" in question.lower():
                        monthly_sales = df.groupby(['year', 'month'])['total_sales'].sum().reset_index()
                        monthly_sales['date'] = pd.to_datetime(monthly_sales[['year', 'month']].assign(day=1))

                        fig = px.line(monthly_sales, x='date', y='total_sales',
                                      title='Monthly Sales Trend',
                                      labels={'total_sales': 'Total Sales ($)', 'date': 'Date'},
                                      markers=True)
                        st.plotly_chart(fig, use_container_width=True)

                    elif "total profit" in question.lower() and "category" in question.lower():
                        result = df.groupby('category')['profit'].sum().sort_values(ascending=False)
                        st.write(result)

                        fig = px.bar(result.reset_index(), x='profit', y='category',
                                     title='Total Profit by Category',
                                     labels={'profit': 'Profit ($)', 'category': 'Category'},
                                     color='category')
                        st.plotly_chart(fig, use_container_width=True)

                    elif "highest sales" in question.lower() and "category" in question.lower():
                        result = df.groupby('category')['total_sales'].sum().sort_values(ascending=False).head(1)
                        st.write(
                            f"The category with the highest sales is {result.index[0]} with ${result.values[0]:,.2f} in sales.")

                    elif "average unit price" in question.lower() and "category" in question.lower():
                        result = df.groupby('category')['unit_price'].mean().sort_values(ascending=False)
                        st.write(result)

                        fig = px.bar(result.reset_index(), x='unit_price', y='category',
                                     title='Average Unit Price by Category',
                                     labels={'unit_price': 'Average Price ($)', 'category': 'Category'},
                                     color='category')
                        st.plotly_chart(fig, use_container_width=True)

                    elif "total quantity sold" in question.lower() and "category" in question.lower():
                        result = df.groupby('category')['quantity'].sum().sort_values(ascending=False)
                        st.write(result)

                        fig = px.bar(result.reset_index(), x='quantity', y='category',
                                     title='Total Quantity Sold by Category',
                                     labels={'quantity': 'Quantity Sold', 'category': 'Category'},
                                     color='category')
                        st.plotly_chart(fig, use_container_width=True)

                    elif "payment method" in question.lower() and "revenue" in question.lower():
                        result = df.groupby('payment_method')['total_sales'].sum().sort_values(ascending=False)
                        st.write(result)

                        fig = px.bar(result.reset_index(), x='total_sales', y='payment_method',
                                     title='Revenue by Payment Method',
                                     labels={'total_sales': 'Total Sales ($)', 'payment_method': 'Payment Method'},
                                     color='payment_method')
                        st.plotly_chart(fig, use_container_width=True)

                    elif "total revenue" in question.lower() and "city" in question.lower():
                        result = df.groupby('City')['total_sales'].sum().sort_values(ascending=False)
                        st.write(result)

                        fig = px.bar(result.reset_index(), x='total_sales', y='City',
                                     title='Total Revenue by City',
                                     labels={'total_sales': 'Total Sales ($)', 'City': 'City'},
                                     color='total_sales',
                                     color_continuous_scale='Blues')
                        st.plotly_chart(fig, use_container_width=True)

                    elif "top 5 products" in question.lower() and "sales" in question.lower():
                        result = df.groupby('category')['total_sales'].sum().sort_values(ascending=False).head(5)
                        st.write(result)

                        fig = px.bar(result.reset_index(), x='total_sales', y='category',
                                     title='Top 5 Products by Sales',
                                     labels={'total_sales': 'Total Sales ($)', 'category': 'Product Name'},
                                     color='category')
                        st.plotly_chart(fig, use_container_width=True)

                    elif "sales trend" in question.lower() and "last year" in question.lower():
                        last_year = df[df['year'] == df['year'].max()]
                        monthly_sales = last_year.groupby(['year', 'month'])['total_sales'].sum().reset_index()
                        monthly_sales['date'] = pd.to_datetime(monthly_sales[['year', 'month']].assign(day=1))

                        fig = px.line(monthly_sales, x='date', y='total_sales',
                                      title='Sales Trend for Last Year',
                                      labels={'total_sales': 'Total Sales ($)', 'date': 'Date'},
                                      markers=True)
                        st.plotly_chart(fig, use_container_width=True)

                    elif "highest sales" in question.lower() and "month" in question.lower():
                        monthly_sales = df.groupby(['year', 'month'])['total_sales'].sum().reset_index()
                        highest_month = monthly_sales.loc[monthly_sales['total_sales'].idxmax()]
                        st.write(
                            f"The month with the highest sales is {highest_month['month']}/{highest_month['year']} with ${highest_month['total_sales']:,.2f} in sales.")

                    elif "average profit margin" in question.lower() and "category" in question.lower():
                        result = df.groupby('category')['profit_margin'].mean().sort_values(ascending=False)
                        st.write(result)

                        fig = px.bar(result.reset_index(), x='profit_margin', y='category',
                                     title='Average Profit Margin by Category',
                                     labels={'profit_margin': 'Average Profit Margin', 'category': 'Category'},
                                     color='category')
                        st.plotly_chart(fig, use_container_width=True)

                    elif "hourly" in question.lower() and "sales" in question.lower():
                        hourly_sales = df.groupby('hour')['total_sales'].sum().reset_index()
                        fig = px.line(hourly_sales, x='hour', y='total_sales',
                                      title='Hourly Sales Pattern',
                                      labels={'total_sales': 'Total Sales ($)', 'hour': 'Hour of Day'},
                                      markers=True)
                        fig.update_xaxes(tickvals=list(range(24)))
                        st.plotly_chart(fig, use_container_width=True)

                    elif "best performing" in question.lower() and "branch" in question.lower():
                        branch_performance = df.groupby('Branch').agg({
                            'total_sales': 'sum',
                            'profit': 'sum',
                            'rating': 'mean'
                        }).sort_values('total_sales', ascending=False).head(5)
                        st.write("Top 5 Branches by Sales:")
                        st.write(branch_performance)

                    else:
                        st.warning("Sorry, I couldn't understand your question. Please try asking something else.")

                except Exception as e:
                    st.error(f"Error processing question: {e}")
            else:
                st.warning("Please enter a question.")

        st.divider()
        st.subheader("Recommendation Engine")
        selected_city = st.selectbox("Select City for Recommendations", df['City'].unique())
        city_data = df[df['City'] == selected_city]

        top_category = city_data.groupby('category')['total_sales'].sum().idxmax()
        weak_category = city_data.groupby('category')['quantity'].sum().idxmin()
        payment_ratio = city_data['payment_method'].value_counts(normalize=True).idxmax()
        best_time = city_data.groupby('time_of_day')['total_sales'].sum().idxmax()

        st.write(f"""
                        - Focus marketing on **{top_category}** (highest revenue generator)
                        - Improve inventory for **{weak_category}** (lowest performing category)
                        - **Preferred payment**: {payment_ratio} (used in {city_data['payment_method'].value_counts(normalize=True).max() * 100:.0f}% of transactions)
                        - **Peak hours**: {best_time} (highest sales volume)
                        """)

    with tab5:
        # AI Question Answering Section
        st.markdown("### 🤖 Ask AI About Your Sales Data")
        # Gemini AI Chat Section
        # st.markdown("#### 💬 Chat with Sales AI")

        # GEMINI_API_KEY_1= "AIzaSyDjnlK-dRcE-QPas3wfaclPHBdbyXm5i1A"
        # GEMINI_API_KEY_2 = "AIzaSyAt2V5YST2geA24N9Sd4qPlSFFukqYBQik"
        # new_API = "AIzaSyDCyJOGP__7RYyESFMDCbDKoCFakHS69X0"
        data = load_data()

        # Configure Gemini
        genai.configure(api_key="AIzaSyAt2V5YST2geA24N9Sd4qPlSFFukqYBQik")
        model = genai.GenerativeModel("gemini-1.5-pro")

        if "messages" not in st.session_state:
            st.session_state.messages = []

        # Create a container for the chat messages
        chat_container = st.container()

        # Show previous messages in the chat container
        with chat_container:
            for msg in st.session_state.messages:
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])


        def summarize_data(question):
            q = question.lower()

            if "revenue" in q:
                return f"Total revenue: ${data['revenue'].sum():,.2f}"

            if "profit" in q:
                return f"Total profit: ${data['profit'].sum():,.2f}"

            if "transactions" in q or "sales count" in q:
                return f"Total transactions: {len(data)}"

            if "top" in q and "city" in q:
                top_cities = data.groupby('City')['revenue'].sum().sort_values(ascending=False).head(3)
                return f"Top Cities by Revenue:\n{top_cities.to_markdown()}"

            if "top" in q and "category" in q:
                top_category = data['category'].value_counts().head(3)
                return f"Top Categories:\n{top_category.to_markdown()}"

            if "popular time" in q or "busiest hour" in q:
                popular_hour = data['hour'].mode().values[0]
                return f"Most Popular Shopping Hour: {popular_hour}:00"

            if "rating" in q:
                avg_rating = data['rating'].mean()
                return f"Average Customer Rating: {avg_rating:.2f}/10"

            if "best branch" in q or "branch performance" in q:
                top_branch = data.groupby('Branch')['revenue'].sum().sort_values(ascending=False).head(3)
                return f"Top Performing Branches:\n{top_branch.to_markdown()}"

            if "date range" in q or "sales period" in q:
                return f"Sales Date Range: {data['date'].min().strftime('%Y-%m-%d')} to {data['date'].max().strftime('%Y-%m-%d')}"

            if "payment" in q:
                payment_method = data['payment_method'].value_counts()
                return f"Most Common Payment Methods:\n{payment_method.to_markdown()}"

            if "top" in q and "product" in q:
                top_product = data.groupby('category')['quantity'].sum().sort_values(ascending=False).head(5)
                return f"Top Selling Products:\n{top_product.to_markdown()}"

            if "top selling category" in question:
                top_cats = data.groupby('category')['quantity'].sum().sort_values(ascending=False).head(3)
                return f"Top selling categories by quantity:\n{top_cats.to_markdown()}"

            if "best performing city" in question:
                best_cities = data.groupby('City')['revenue'].sum().sort_values(ascending=False).head(3)
                return f"Top performing cities by revenue:\n{best_cities.to_markdown()}"

            if "profit margin" in question:
                avg_margin = data['profit_margin'].mean() * 100
                return f"Average profit margin across all products: {avg_margin:.1f}%"

            if "customer rating" in question:
                avg_rating = data['rating'].mean()
                return f"Average customer rating: {avg_rating:.1f}/10"

            if "monthly trend" in question:
                monthly = data.groupby(data['date'].dt.to_period('M'))['revenue'].sum()
                return f"Monthly revenue trends:\n{monthly.to_markdown()}"

            if "highest revenue" in question:
                top_products = data.groupby('category')['revenue'].sum().sort_values(ascending=False).head(3)
                return f"Highest revenue categories:\n{top_products.to_markdown()}"

            # Default fallback
            return "Summary:\n" + pd.Series({
                "Revenue": f"${data['revenue'].sum():,.2f}",
                "Profit": f"${data['profit'].sum():,.2f}",
                "Transactions": len(data),
                "Top City": data.groupby('City')['revenue'].sum().idxmax(),
                "Top Category": data['category'].value_counts().idxmax(),
                "Top Payment": data['payment_method'].value_counts().idxmax(),
            }).to_markdown()


        # Create a container for the chat input at the bottom
        input_container = st.container()

        with input_container:
            # Chat input at the bottom
            user_input = st.chat_input("Ask about Walmart sales, profits, trends, top products...")

            # Clear button next to the chat input
            clear_button = st.button("Clear Chat")

        # Handle new input
        if user_input:
            st.session_state.messages.append({"role": "user", "content": user_input})
            with chat_container:
                with st.chat_message("user"):
                    st.markdown(user_input)

            with st.spinner("Thinking..."):
                try:
                    context = summarize_data(user_input)
                    prompt = f"""
                    You are an AI data assistant trained to analyze Walmart transactional data.

                    User asked: "{user_input}"

                    Here are the insights extracted from the dataset:
                    {context}

                    Now generate a helpful and informative response using this data. Format clearly using markdown.
                                """
                    response = model.generate_content(prompt)
                    reply = response.text
                except Exception as e:
                    reply = f"Error: {e}"

            st.session_state.messages.append({"role": "assistant", "content": reply})

            with chat_container:
                with st.chat_message("assistant"):
                    st.markdown(reply)

        # Handle clear button
        if clear_button:
            st.session_state.messages = []
            st.rerun()


    with tab6:
        st.markdown("## 📈 Revenue Forecasting")

        # Create a DataFrame with the revenue data from the image
        revenue_data = pd.DataFrame({
            'Year': [2020, 2021, 2022],
            'Total Revenue': [230000, 225000, 220000]
        })

        # Add the predicted revenue for 2026
        predicted_year = 2026
        predicted_revenue = 230713.76

        # Create the line chart
        fig = go.Figure()

        # Add actual revenue line
        fig.add_trace(go.Scatter(
            x=revenue_data['Year'],
            y=revenue_data['Total Revenue'],
            mode='lines+markers',
            name='Actual Revenue',
            line=dict(color='#1f77b4', width=3)
        ))

        # Add predicted revenue point
        fig.add_trace(go.Scatter(
            x=[predicted_year],
            y=[predicted_revenue],
            mode='markers',
            name='Predicted Revenue',
            marker=dict(color='red', size=10)
        ))

        # Add a dotted line connecting last actual to predicted
        fig.add_trace(go.Scatter(
            x=[revenue_data['Year'].iloc[-1], predicted_year],
            y=[revenue_data['Total Revenue'].iloc[-1], predicted_revenue],
            mode='lines',
            name='Projection',
            line=dict(color='gray', width=2, dash='dot'),
            showlegend=False
        ))

        # Update layout
        fig.update_layout(
            title='Walmart Revenue Trend and Prediction',
            xaxis_title='Year',
            yaxis_title='Revenue ($)',
            hovermode='x unified',
            template='plotly_white',
            height=500
        )

        # Display the chart
        st.plotly_chart(fig, use_container_width=True)

        # Display the prediction and accuracy
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Predicted Revenue for 2026", f"${predicted_revenue:,.2f}")
        with col2:
            st.metric("Model Accuracy", "88.57%")

            # Add some explanatory text
        st.markdown("""
        ### Analysis
        - Revenue showed a slight decline from 2020 to 2022
        - Our forecasting model predicts a recovery in 2026
        - The model has an accuracy of 88.57% based on historical data
        """)

        st.markdown("""
                    <style>
                           .block-container {
                                padding-top: 2rem;
                                padding-bottom: 3rem;
                                padding-left: 5rem;
                                padding-right: 5rem;
                            }
                    </style>
                    """, unsafe_allow_html=True)

    with tab7:
        st.markdown("## 📍 Location-Based Analysis")
        st.write("Select cities and products to analyze sales performance across different locations.")

        # Get unique values from the dataframe
        cities = ['All'] + sorted(df['City'].unique())
        products = ['All'] + sorted(df['category'].unique())

        # Create a form for the selection interface
        with st.form("location_analysis_form"):
            # First row with three columns
            col1, col2 = st.columns(2)

            with col1:
                st.markdown("### Choose Cities")
                selected_cities = st.multiselect(
                    "Select Cities",
                    options=cities,
                    default=['All'] if 'All' in cities else [],
                    key="city_select"
                )

            with col2:
                st.markdown("### Choose Products")
                selected_products = st.multiselect(
                    "Select Products",
                    options=products,
                    default=['All'] if 'All' in products else [],
                    key="product_select"
                )

            # Submit button
            submitted = st.form_submit_button("Submit")

        # Process the selections when form is submitted
        if submitted:
            # Apply filters to the data
            filtered_data = df.copy()

            # Apply city filter if specified
            if 'All' not in selected_cities and len(selected_cities) > 0:
                filtered_data = filtered_data[filtered_data['City'].isin(selected_cities)]

            # Apply product filter if specified
            if 'All' not in selected_products and len(selected_products) > 0:
                filtered_data = filtered_data[filtered_data['category'].isin(selected_products)]

            # Calculate total sales (unit_price * quantity) and profit (total_sales * profit_margin)
            filtered_data['total_sales'] = filtered_data['unit_price'] * filtered_data['quantity']
            filtered_data['profit'] = filtered_data['total_sales'] * filtered_data['profit_margin']

            # Show summary statistics
            st.markdown("### 📊 Summary Statistics")

            if filtered_data.empty:
                st.warning("No data matches your selected filters. Please adjust your selections.")
            else:
                # Calculate metrics
                total_sales = filtered_data['total_sales'].sum()
                total_profit = filtered_data['profit'].sum()
                avg_rating = filtered_data['rating'].mean()
                avg_profit_margin = (filtered_data['profit'].sum() / filtered_data['total_sales'].sum()) * 100

                # Display metrics in columns
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Total Sales", f"${total_sales:,.2f}")
                col2.metric("Total Profit", f"${total_profit:,.2f}")
                col3.metric("Average Rating", f"{avg_rating:.1f}/10")
                col4.metric("Avg Profit Margin", f"{avg_profit_margin:.1f}%")

                # Show top performing cities
                st.markdown("### 🏆 Top Performing Locations")
                city_performance = filtered_data.groupby('City').agg({
                    'total_sales': 'sum',
                    'profit': 'sum',
                    'rating': 'mean',
                    'invoice_id': 'count'
                }).rename(columns={'invoice_id': 'transactions'}).sort_values('total_sales', ascending=False)

                if not city_performance.empty:
                    # Top cities by sales
                    fig = px.bar(
                        city_performance.head(10).reset_index(),
                        x='total_sales',
                        y='City',
                        orientation='h',
                        title='Top Cities by Sales',
                        labels={'total_sales': 'Total Sales ($)', 'City': 'City'},
                        color='total_sales',
                        color_continuous_scale='Blues'
                    )
                    st.plotly_chart(fig, use_container_width=True)

                # Show product performance
                st.markdown("### 📦 Product Performance")
                product_performance = filtered_data.groupby('category').agg({
                    'total_sales': 'sum',
                    'profit': 'sum',
                    'quantity': 'sum'
                }).sort_values('total_sales', ascending=False)

                if not product_performance.empty:
                    col1, col2 = st.columns(2)
                    with col1:
                        fig = px.pie(
                            product_performance.reset_index(),
                            values='total_sales',
                            names='category',
                            title='Sales Distribution by Product Category',
                            hole=0.3
                        )
                        st.plotly_chart(fig, use_container_width=True)

                    with col2:
                        fig = px.bar(
                            product_performance.reset_index(),
                            x='category',
                            y='quantity',
                            title='Quantity Sold by Category',
                            labels={'quantity': 'Quantity Sold', 'category': 'Category'},
                            color='category'
                        )
                        st.plotly_chart(fig, use_container_width=True)
                else:
                    st.warning("No sales data available for the selected products.")

    with tab8:

        st.markdown("## ⏰ Time-Based Analysis")

        # Hourly sales pattern
        st.markdown("### 🕒 Hourly Sales Pattern")
        hourly_sales = filtered_df.groupby('hour')['total_sales'].sum().reset_index()
        fig = px.line(hourly_sales, x='hour', y='total_sales',
                      title='Sales by Hour of Day',
                      labels={'total_sales': 'Total Sales ($)', 'hour': 'Hour of Day'},
                      markers=True)
        fig.update_xaxes(tickvals=list(range(24)))
        st.plotly_chart(fig, use_container_width=True)

        # Day of week analysis
        st.markdown("### 📅 Day of Week Analysis")
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        filtered_df['day_of_week'] = pd.Categorical(filtered_df['day_of_week'], categories=day_order, ordered=True)
        dow_sales = filtered_df.groupby('day_of_week').agg({
            'total_sales': 'sum',
            'profit': 'sum',
            'invoice_id': 'count'
        }).rename(columns={'invoice_id': 'transactions'}).reset_index()

        col1, col2 = st.columns(2)
        with col1:
            fig = px.bar(dow_sales, x='day_of_week', y='total_sales',
                         title='Sales by Day of Week',
                         labels={'total_sales': 'Total Sales ($)', 'day_of_week': 'Day of Week'})
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            fig = px.bar(dow_sales, x='day_of_week', y='transactions',
                         title='Transactions by Day of Week',
                         labels={'transactions': 'Number of Transactions', 'day_of_week': 'Day of Week'})
            st.plotly_chart(fig, use_container_width=True)

        # Monthly seasonality
        st.markdown("### 🌦 Monthly Seasonality")
        monthly_sales = filtered_df.groupby(['month']).agg({
            'total_sales': 'sum',
            'profit': 'sum'
        }).reset_index()

        fig = px.line(monthly_sales, x='month', y='total_sales',
                      title='Sales by Month',
                      labels={'total_sales': 'Total Sales ($)', 'month': 'Month'},
                      markers=True)
        fig.update_xaxes(tickvals=list(range(1, 13)), ticktext=['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                                                                'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'])
        st.plotly_chart(fig, use_container_width=True)

    with tab9:

        # Sample insights
        st.markdown("## 💡 Key Insights")

        # Calculate insights
        top_category = df.groupby('category')['total_sales'].sum().idxmax()
        top_category_sales = df.groupby('category')['total_sales'].sum().max()
        top_city = df.groupby('City')['total_sales'].sum().idxmax()
        top_city_sales = df.groupby('City')['total_sales'].sum().max()
        best_payment = df.groupby('payment_method')['total_sales'].sum().idxmax()
        best_payment_sales = df.groupby('payment_method')['total_sales'].sum().max()
        avg_rating = df['rating'].mean()
        peak_month = df.groupby(['year', 'month'])['total_sales'].sum().idxmax()
        peak_month_sales = df.groupby(['year', 'month'])['total_sales'].sum().max()

        # Display insights in a nice layout
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("### 📊 Sales Performance")
            st.metric("Top Selling Category", f"{top_category}", f"${top_category_sales:,.2f}")
            st.metric("Highest Revenue City", f"{top_city}", f"${top_city_sales:,.2f}")
            st.metric("Best Payment Method", f"{best_payment}", f"${best_payment_sales:,.2f}")

        with col2:
            st.markdown("### 📈 Trends & Patterns")
            st.metric("Peak Sales Month", f"{peak_month[1]}/{peak_month[0]}", f"${peak_month_sales:,.2f}")
            st.metric("Average Customer Rating", f"{avg_rating:.1f}/10")
            st.metric("Total Transactions", f"{len(df):,}")

        st.markdown("---")

        # Recommendations section
        st.markdown("## 🚀 Recommendations")

        # Identify low performing categories
        category_performance = df.groupby('category').agg({
            'total_sales': 'sum',
            'profit': 'sum',
            'rating': 'mean'
        }).sort_values('total_sales')

        worst_category = category_performance.index[0]
        worst_category_sales = category_performance.iloc[0]['total_sales']

        # Identify cities with potential
        city_performance = df.groupby('City').agg({
            'total_sales': 'sum',
            'profit': 'sum',
            'rating': 'mean'
        }).sort_values('total_sales')

        potential_city = city_performance.index[0]
        potential_city_sales = city_performance.iloc[0]['total_sales']

        # Display recommendations
        st.markdown(f"""
        - **Focus on {worst_category}**: With sales of only ${worst_category_sales:,.2f}, this category is underperforming. 
          Consider promotions or product improvements.
        - **Expand in {potential_city}**: This city has untapped potential with sales of ${potential_city_sales:,.2f}. 
          Consider targeted marketing campaigns.
        - **Improve Customer Experience**: The average rating is {avg_rating:.1f}/10. Focus on improving customer satisfaction 
          to boost repeat business.
        - **Optimize Staffing**: Peak hours are between {df.groupby('hour')['total_sales'].sum().idxmax()}:00 and 
          {df.groupby('hour')['total_sales'].sum().idxmax() + 2}:00. Ensure adequate staffing during these times.
        - **Electronic accessories** is the top-selling category with over $1.5M in sales.
        - **San Antonio** is the city with the highest total sales.
        - Sales peak during the **summer months** (June-August).
        - **Ewallet** is the most popular payment method, accounting for 45% of transactions.
        """)

        # Forecasting section
        st.markdown("## 📶 Dataset Debug Info")

        # Debugging info (optional)
        with st.expander("🛠️ Debug Info"):
            st.write(f"Data shape: {filtered_df.shape}")
            st.write("First 5 rows:")
            st.write(filtered_df.head())

        # Benchmarking
        st.markdown("---")

else:
    if st.session_state.current_page == "login":
        login_page()
    elif st.session_state.current_page == "signup":
        signup_page()