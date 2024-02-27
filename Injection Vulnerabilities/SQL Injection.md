**SQL Injection (SQLi):**

**Description:**
SQL Injection is a type of attack where an attacker injects malicious SQL code into input fields or parameters of a web application, leading to unauthorized access, manipulation, or deletion of data in the database. SQL Injection attacks can occur when user input is directly concatenated into SQL queries without proper validation or sanitization.

**How it's done:**
1. **User Input Manipulation:**
   - An attacker provides specially crafted input containing SQL code, often using input fields on a website.

2. **Malicious SQL Queries:**
   - The injected SQL code alters the intended query structure, allowing the attacker to execute unauthorized SQL commands.

3. **Data Access and Manipulation:**
   - The manipulated SQL queries may lead to unauthorized access to sensitive data, modification of data, or even deletion of entire tables.

**Countermeasures:**

1. **Parameterized Statements (Prepared Statements):**
   - Use parameterized statements or prepared statements to ensure that user input is treated as data and not executable code.

   ```python
   # Using parameterized statements in Python (with SQLite)
   import sqlite3

   conn = sqlite3.connect('database.db')
   cursor = conn.cursor()

   username = input("Enter username: ")
   password = input("Enter password: ")

   # Safe parameterized query
   cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
   ```

2. **Stored Procedures:**
   - Utilize stored procedures to encapsulate SQL logic within the database, reducing the risk of injection.

   ```sql
   -- Example stored procedure (MySQL syntax)
   DELIMITER //
   CREATE PROCEDURE GetUserData (IN userId INT)
   BEGIN
       SELECT * FROM users WHERE id = userId;
   END //
   DELIMITER ;
   ```

   ```python
   # Calling a stored procedure in Python (with MySQL)
   import mysql.connector

   conn = mysql.connector.connect(user='username', password='password', database='database')
   cursor = conn.cursor()

   user_id = input("Enter user ID: ")

   # Calling the stored procedure
   cursor.callproc('GetUserData', (user_id,))
   ```

3. **Input Validation and Sanitization:**
   - Validate and sanitize user input to ensure it adheres to expected formats and does not contain malicious characters.

   ```python
   # Input validation in Python
   def validate_input(input_str):
       if not input_str.isalnum():
           raise ValueError("Invalid input")
       return input_str

   username = validate_input(input("Enter username: "))
   ```

4. **Least Privilege Principle:**
   - Assign the minimum required privileges to database users. Avoid using a superuser account for web application connections.

   ```sql
   -- Example: Creating a limited-privilege user in PostgreSQL
   CREATE USER web_app_user WITH PASSWORD 'password';
   GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO web_app_user;
   ```

5. **Database Firewalls:**
   - Implement database firewalls that can detect and prevent unusual or malicious SQL queries.

6. **ORMs (Object-Relational Mappers):**
   - Use ORMs to interact with the database in a way that abstracts SQL queries, reducing the risk of injection.

   ```python
   # Using an ORM (SQLAlchemy in this case)
   from sqlalchemy import create_engine, Column, Integer, String
   from sqlalchemy.ext.declarative import declarative_base
   from sqlalchemy.orm import sessionmaker

   Base = declarative_base()

   class User(Base):
       __tablename__ = 'users'

       id = Column(Integer, primary_key=True)
       username = Column(String)
       password = Column(String)

   engine = create_engine('sqlite:///database.db')
   Base.metadata.create_all(engine)

   Session = sessionmaker(bind=engine)
   session = Session()

   username = input("Enter username: ")
   password = input("Enter password: ")

   # Safe ORM query
   user = session.query(User).filter_by(username=username, password=password).first()
   ```

7. **Security Education:**
   - Educate developers about the risks of SQL Injection and best practices for writing secure code.

Implementing a combination of these countermeasures is crucial to mitigate the risk of SQL Injection attacks. Regular code reviews, security audits, and testing are essential to identify and address potential vulnerabilities in your application.


8. **Content Security Policy (CSP):**
   - Implement Content Security Policy headers to mitigate the impact of possible XSS attacks, which could be used to execute SQL Injection.

   ```html
   <!-- Example Content Security Policy header -->
   <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://trusted-scripts.com;">
   ```

9. **Regular Expression Whitelisting:**
   - Use regular expressions to create whitelists for expected input patterns, helping to filter out potentially malicious characters.

   ```python
   import re

   def sanitize_input(input_str):
       # Define a regular expression pattern for allowed characters
       allowed_pattern = re.compile(r'^[a-zA-Z0-9_\-]+$')

       if not allowed_pattern.match(input_str):
           raise ValueError("Invalid input")

       return input_str
   ```

10. **Database Connection Pooling:**
    - Implement database connection pooling to reuse database connections efficiently, reducing the likelihood of time-based attacks.

    ```python
    # Using connection pooling in Python (with psycopg2)
    from psycopg2 import pool

    # Create a connection pool
    connection_pool = pool.SimpleConnectionPool(
        1,  # Minimum connections
        10,  # Maximum connections
        user='username',
        password='password',
        host='localhost',
        database='database'
    )

    # Acquire a connection from the pool
    connection = connection_pool.getconn()
    ```

11. **Logging and Monitoring:**
    - Set up extensive logging to detect and log any suspicious SQL queries. Regularly monitor these logs for unusual patterns.

    ```python
    # Example SQL query logging in Python (with Flask and SQLAlchemy)
    from flask import Flask
    from flask_sqlalchemy import SQLAlchemy
    import logging

    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Enable SQLAlchemy query logging
    logging.basicConfig()
    logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

    db = SQLAlchemy(app)
    ```

12. **Database Auditing:**
    - Enable database auditing features to track and log all database activities. This can help identify and respond to potential SQL Injection attempts.

    ```sql
    -- Example enabling auditing in PostgreSQL
    ALTER SYSTEM SET audit_trail = 'on';
    ```

13. **Static Analysis Tools:**
    - Use static analysis tools during development to automatically identify potential SQL Injection vulnerabilities in the codebase.

14. **Regular Code Reviews:**
    - Conduct regular code reviews with a focus on SQL Injection prevention, ensuring that best practices are followed and potential vulnerabilities are identified early.

15. **Patch and Update Database Software:**
    - Keep the database software up-to-date with the latest security patches to ensure that known vulnerabilities are addressed promptly.

16. **Error Handling:**
    - Implement proper error handling to avoid leaking sensitive information in error messages. Provide generic error messages to users.

    ```python
    # Example generic error message in Python
    try:
        # SQL query execution
    except Exception as e:
        log.error("Error executing SQL query: %s", str(e))
        return "An error occurred while processing your request. Please try again later."
    ```

17. **Dynamic Queries with Whitelisting:**
    - If dynamic queries are unavoidable, use parameterized statements along with a whitelist of allowed values to limit potential injection points.

    ```python
    # Dynamic query with whitelisting in Python (with SQLAlchemy)
    from sqlalchemy.sql import text

    def dynamic_query(user_input):
        allowed_columns = ['username', 'email']

        if user_input not in allowed_columns:
            raise ValueError("Invalid input")

        query = text(f"SELECT {user_input} FROM users")
        result = db.engine.execute(query)

        return result.fetchall()
    ```

18. **Database Role Separation:**
    - Separate database roles and permissions based on the principle of least privilege, restricting the ability to execute certain types of queries.

    ```sql
    -- Example: Creating a read-only user in MySQL
    CREATE USER 'readonly_user'@'localhost' IDENTIFIED BY 'password';
    GRANT SELECT ON *.* TO 'readonly_user'@'localhost';
    ```

Implementing a combination of these countermeasures helps strengthen your application's defenses against SQL Injection attacks. Remember to adapt these measures to your specific programming language, framework, and database technology. Regularly review and update your security practices to stay ahead of emerging threats.
