import streamlit as st
import sqlite3
import hashlib
import os
from datetime import datetime
import pandas as pd
import io
import concurrent.futures

conn = sqlite3.connect("auth.db")
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        file_name TEXT,
        file_content TEXT,  -- Change BLOB to TEXT to store CSV data as text
        upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')


conn.commit()

def user_exists(username):
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    return cursor.fetchone() is not None

def verify_password(username, password):
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    user_data = cursor.fetchone()
    if user_data:
        hashed_password = user_data[0]
        return hashlib.sha256(password.encode()).hexdigest() == hashed_password
    return False

def signup():
    st.title("Signup")
    new_username = st.text_input("Username (Signup)")
    new_password = st.text_input("Password (Signup)", type="password")
    if st.button("Sign Up"):
        if user_exists(new_username):
            st.error("Username already exists. Please choose a different one.")
        else:
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (new_username, hashed_password))
            conn.commit()
            st.success("Signup successful! You can now log in.")

def login():
    st.title("Login")
    username = st.text_input("Username (Login)")
    password = st.text_input("Password (Login)", type="password")
    if st.button("Log In"):
        if not username:
            st.error("Please enter a username.")
        elif not password:
            st.error("Please enter a password.")
        elif not user_exists(username):
            st.error("Username doesn't exist. Please sign up first.")
        elif not verify_password(username, password):
            st.error("Incorrect password. Please try again.")
        else:
            st.success(f"Welcome, {username}!")
            st.session_state.logged_in = True
            st.session_state.username = username 


def file_upload_and_display():
    st.title("CSV File Viewer")
    if st.session_state.logged_in:
        user_id = get_user_id(st.session_state.username)
        st.button("Log Out", on_click=logout)
        uploaded_file = st.file_uploader("Upload a CSV file", type=["csv"])
        if uploaded_file is not None:
            with st.spinner("Uploading and processing..."):
                file_path, file_contents = save_uploaded_file_to_db(uploaded_file, user_id, conn)
                st.subheader("File Content (CSV):")
                st.write(file_contents)
                st.success(f"CSV file saved to: {file_path}")


        st.sidebar.title("File History")
        user_files = get_user_files(st.session_state.username)

        if user_files:
            for i, file in enumerate(user_files):
                file_name = file[0]
                unique_key = f"{i}_{file_name}"  
                if st.sidebar.button(file_name, key=unique_key):
                    display_file_content(user_id, file_name)
    else:
        st.error("You need to be logged in to upload files.")



# def save_uploaded_file_to_db(uploaded_file, user_id, conn):
#     file_name = uploaded_file.name
#     file_contents = uploaded_file.read()
    
#     encodings = ['utf-8', 'latin-1', 'ISO-8859-1']  # List of possible encodings to try

#     cursor = conn.cursor()

#     for encoding in encodings:
#         try:
#             file_contents = file_contents.decode(encoding)
#             break  
#         except UnicodeDecodeError:
#             continue  

#     cursor.execute("INSERT INTO files (user_id, file_name, file_content) VALUES (?, ?, ?)",
#                    (user_id, file_name, file_contents))
#     conn.commit()
#     return file_name, file_contents
def save_uploaded_file_to_db(uploaded_file, user_id, conn):
    file_name = uploaded_file.name
    file_contents = uploaded_file.read()
    
    cursor = conn.cursor()

    cursor.execute("INSERT INTO files (user_id, file_name, file_content) VALUES (?, ?, ?)",
                   (user_id, file_name, file_contents))
    conn.commit()
    return file_name, file_contents



def get_user_files(username):
    user_id = get_user_id(username)
    if user_id:
        cursor.execute("SELECT file_name FROM files WHERE user_id = ?", (user_id,))
        return cursor.fetchall()
    return None


def get_user_id(username):
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_data = cursor.fetchone()
    if user_data:
        return user_data[0]
    return None



# def display_file_content(user_id, file_name):
#     cursor.execute("SELECT file_content FROM files WHERE user_id = ? AND file_name = ?", (user_id, file_name))
#     file_contents = cursor.fetchone()
#     if file_contents:
#         file_contents = file_contents[0]
#         try:
#             df = pd.read_csv(pd.compat.StringIO(file_contents))
#             st.subheader(f"CSV Data of {file_name}:")
#             st.write(df)
#         except pd.errors.ParserError:
#             st.warning("Unable to display the file as CSV.")
#     else:
#         st.warning("File not found.")
#2222222
# def display_file_content(user_id, file_name):
#     cursor.execute("SELECT file_content FROM files WHERE user_id = ? AND file_name = ?", (user_id, file_name))
#     file_contents = cursor.fetchone()
#     if file_contents:
#         file_contents = file_contents[0]
#         try:
#             # Use io.StringIO instead of pd.compat.StringIO
#             df = pd.read_csv(io.StringIO(file_contents))
#             st.subheader(f"CSV Data of {file_name}:")
#             st.write(df)
#         except pd.errors.ParserError:
#             st.warning("Unable to display the file as CSV.")
#     else:
#         st.warning("File not found.")
def display_file_content(user_id, file_name):
    cursor.execute("SELECT file_content FROM files WHERE user_id = ? AND file_name = ?", (user_id, file_name))
    file_contents = cursor.fetchone()
    if file_contents:
        file_contents = file_contents[0]
        try:
            # Use io.BytesIO to read binary data
            with io.BytesIO(file_contents) as f:
                df = pd.read_csv(f)
                st.subheader(f"CSV Data of {file_name}:")
                st.write(df)
        except pd.errors.ParserError:
            st.warning("Unable to display the file as CSV.")
    else:
        st.warning("File not found.")





def logout():
    st.session_state.logged_in = False
    st.session_state.username = None







def display_user_files(username):
    st.title("Your Uploaded Files")
    user_id = get_user_id(username)
    if user_id:
        cursor.execute("SELECT file_name, upload_time, LENGTH(file_content) FROM files WHERE user_id = ?", (user_id,))
        files = cursor.fetchall()
        if files:
            st.subheader("File History:")
            for file in files:
                file_name, upload_time, file_size = file
                upload_time = datetime.fromisoformat(upload_time)
                file_type = file_name.split(".")[-1]
                st.write(f"File Name: {file_name}")
                st.write(f"Uploaded on: {upload_time}")
                st.write(f"File Size: {file_size} bytes")
                st.write(f"File Type: {file_type.upper()}")
                st.write("---")
        else:
            st.write("You haven't uploaded any files yet.")

def main():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        signup()
        login()
    else:
        file_upload_and_display()
        display_user_files(st.session_state.username)

if __name__ == "__main__":
    main()
