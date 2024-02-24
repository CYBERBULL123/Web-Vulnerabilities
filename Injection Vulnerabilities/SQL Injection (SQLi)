
### SQL Injection (SQLi):

**Description:**
SQL Injection occurs when an attacker injects malicious SQL code into input fields, manipulating the database queries to gain unauthorized access or retrieve sensitive information.

**Countermeasures:**
1. Use Parameterized Queries/Prepared Statements:
   - Parameterized queries ensure that user input is treated as data, not executable code.
   - **Example Code:**
     ```python
     import sqlite3

     def execute_query(username):
         conn = sqlite3.connect('database.db')
         cursor = conn.cursor()

         # Using parameterized query
         cursor.execute('SELECT * FROM users WHERE username = ?', (username,))

         result = cursor.fetchall()

         conn.close()
         return result
     ```

2. Input Validation and Whitelisting:
   - Validate user input to ensure it adheres to expected formats.
   - Use whitelisting to only allow specific characters.
   - **Example Code:**
     ```python
     import re

     def validate_username(username):
         if re.match("^[a-zA-Z0-9_-]+$", username):
             return True
         else:
             return False
     ```

