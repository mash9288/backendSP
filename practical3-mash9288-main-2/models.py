from extensions import db, bcrypt
from sqlalchemy import text, exc
from flask_jwt_extended import create_access_token


def create_user_tables():
    user_table_sql = text("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            password VARCHAR(64) NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            status ENUM('0', '1', '2') DEFAULT '0',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB;
    """)

    user_profile_table_sql = text("""
        CREATE TABLE IF NOT EXISTS user_profiles (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            first_name VARCHAR(100) NULL,
            last_name VARCHAR(100) NULL,
            contact_no VARCHAR(15),
            dob DATE NULL,
            bio TEXT,
            country VARCHAR(100) NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        ) ENGINE=InnoDB;
    """)

    images_table_sql = text("""
        CREATE TABLE IF NOT EXISTS images (
            id INT AUTO_INCREMENT PRIMARY KEY,
            image_name VARCHAR(100) NOT NULL,
            image_url VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB;
    """)

    user_image_table_sql = text("""
        CREATE TABLE IF NOT EXISTS user_image (
            user_id INT NOT NULL,
            image_id INT NOT NULL,
            PRIMARY KEY (user_id, image_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (image_id) REFERENCES images(id) ON DELETE CASCADE
        ) ENGINE=InnoDB;
    """)

    roles_table_sql = text("""
        CREATE TABLE IF NOT EXISTS roles (
            id INT AUTO_INCREMENT PRIMARY KEY,
            role_name VARCHAR(80) NOT NULL,
            description TEXT
        ) ENGINE=InnoDB;
    """)

    user_role_table_sql = text("""
        CREATE TABLE IF NOT EXISTS user_role (
            user_id INT NOT NULL,
            role_id INT NOT NULL,
            PRIMARY KEY (user_id, role_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
        ) ENGINE=InnoDB;
    """)

    with db.engine.begin() as connection:
        connection.execute(user_table_sql)
        connection.execute(user_profile_table_sql)
        connection.execute(images_table_sql)
        connection.execute(user_image_table_sql)
        connection.execute(roles_table_sql)
        connection.execute(user_role_table_sql)

def initialize_database():
    create_user_tables()

def authenticate_user_jwt(username, password):
    sql = text("""
    SELECT users.id as user_id, users.password as password, roles.role_name as role 
    FROM users
    LEFT JOIN user_role ON users.id = user_role.user_id
    LEFT JOIN roles ON user_role.role_id = roles.id
    WHERE username = :username;
    """)
    result = db.session.execute(sql, {'username': username})
    user = result.mappings().first()
    if user:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')   # Hash the password
        if bcrypt.check_password_hash(user['password'], password):
            # Create JWT token if authentication is successful
            access_token = create_access_token(identity=str(user['user_id']),
additional_claims={"role": user['role']})
            return access_token # Return the JWT token
    else:
        return None
    # Authentication failed


# USER AUTHENTICATION
def authenticate_user(username, password):
    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    sql = text('SELECT id, password FROM users WHERE username = :username;')
    result = db.session.execute(sql, {'username': username})
    user = result.mappings().first()

    #Check if user exists
    if user:
        #Compare hashed password
        if bcrypt.check_password_hash(user['password'], password):
            return user['id'] # Authentication successful
        else:
            return None # Authentication failed
    else:
        return None # Authentication failed


# CREATE USER
def create_user(username, password, email, role_name):
    try:

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8') # Hash the password
        
        # Insert into users table
        user_sql = text("""
        INSERT INTO users (username, password, email)
        VALUES (:username, :password, :email);
        """)
       
        # Execute the query
        db.session.execute(user_sql, {'username': username, 'password': hashed_password, 'email': email}) 
        # Fetch the ID of the last inserted row
        user_id = db.session.execute(text('SELECT LAST_INSERT_ID();')).fetchone()[0]
 
        get_role_id_sql = text("""
            SELECT id FROM roles WHERE roles.role_name = :role_name;
            """)
       
        result = db.session.execute(get_role_id_sql,{'role_name': role_name})
        role = result.fetchone()
        role_id = role[0]
 
        print(role_id)
 
        assign_role_sql = text("""
            INSERT INTO user_role (user_id, role_id) VALUES (:user_id, :role_id);
            """)
           
        db.session.execute(assign_role_sql,{'user_id': user_id, 'role_id': role_id})
       
        db.session.commit()
        return user_id
   
    except Exception as e:
        # Rollback the transaction in case of error
        db.session.rollback()
        raise e  


# CREATE USER PROFILE
def create_user_profile(user_id, profile_data):
    try:
        profile_sql = text("""
        INSERT INTO user_profiles (user_id, first_name, last_name, contact_no, dob, bio, country) 
        VALUES (:user_id, :first_name, :last_name, :contact_no, :dob, :bio, :country)
        """)
        db.session.execute(profile_sql, {**profile_data, 'user_id': user_id})
        user_profile_id = db.session.execute(text('SELECT LAST_INSERT_ID();')).fetchone()[0]
        db.session.commit()
        return user_profile_id
    except Exception as e:
        db.session.rollback()
        raise e


# CREATE USER IMAGE
def create_user_image(user_id, image_name, image_url):
    try:
        image_sql = text("""
        INSERT INTO images (image_name, image_url) VALUES (:image_name, :image_url)
        """)
        db.session.execute(image_sql, {'image_name': image_name, 'image_url': image_url})
        image_id = db.session.execute(text('SELECT LAST_INSERT_ID();')).fetchone()[0]

        assign_image_sql = text("""
        INSERT INTO user_image (user_id, image_id) VALUES (:user_id, :image_id);
        """)
        db.session.execute(assign_image_sql, {'user_id': user_id, 'image_id': image_id})

        db.session.commit()
        return image_id
    except Exception as e:
        db.session.rollback()
        raise e


# RETRIEVE USER BY ID
def get_user_by_id(user_id):
    try:
        sql = text("SELECT id, username, email FROM users WHERE id = :user_id;")
        result = db.session.execute(sql, {'user_id': user_id})
        user = result.fetchone()

        if user:
            return dict(user)
        else:
            return None
    except Exception as e:
        db.session.rollback()
        raise e


# GET USER DETAILS BY ID
def get_user_details_by_id(user_id):
    try:
        sql = text("""
        SELECT
            users.id as user_id,
            users.username,
            users.email,
            users.status,
            user_profiles.first_name,
            user_profiles.last_name,
            user_profiles.contact_no,
            user_profiles.dob,
            user_profiles.bio,
            user_profiles.country,
            roles.role_name as role_name,
            GROUP_CONCAT(images.image_name) as image_names,
            GROUP_CONCAT(images.image_url) as image_urls
        FROM
            users
        LEFT JOIN
            user_profiles ON users.id = user_profiles.user_id
        LEFT JOIN
            user_image ON users.id = user_image.user_id
        LEFT JOIN
            images ON user_image.image_id = images.id
        LEFT JOIN
            user_role ON users.id = user_roles.user_id
        LEFT JOIN
            roles ON user_role.role_id = roles.id
        WHERE users.id = :user_id
        GROUP BY
            users.id,
            user_profiles.id,
            roles.id;
        """)
        result = db.session.execute(sql, {'user_id': user_id})
        user_details = result.fetchone()
        return dict(user_details) if user_details else None
    except Exception as e:
        db.session.rollback()
        raise e


# UPDATE USER PROFILE
def update_user_profile(user_id, first_name, last_name, contact_no, dob, bio, country):
    try:
        sql = text("UPDATE user_profiles SET first_name = :first_name, last_name = :last_name, contact_no = :contact_no, dob = :dob, bio = :bio, country = :country WHERE user_id = :user_id;")
        result = db.session.execute(sql, {'user_id': user_id, 'first_name': first_name, 'last_name': last_name, 'contact_no': contact_no, 'dob': dob, 'bio': bio, 'country': country})
        db.session.commit()
        if result.rowcount > 0:
            return {"user_id": user_id}
        else:
            return None
    except Exception as e:
        db.session.rollback()
        raise e


# UPDATE USER
def update_user(user_id, username, email):
    try:
        sql = text("UPDATE users SET username = :username, email = :email WHERE id = :user_id;")
        result = db.session.execute(sql, {'user_id': user_id, 'username': username, 'email': email})
        db.session.commit()
        if result.rowcount > 0:
            return {"user_id": user_id}
        else:
            return None
    except Exception as e:
        db.session.rollback()
        raise e


# DELETE USER BY ID
def delete_user_by_id(user_id):
    try:
        sql_delete_user = text("""
        UPDATE users SET status = '2'
        WHERE id = :user_id;
        """)
        result = db.session.execute(sql_delete_user, {'user_id': user_id})
        db.session.commit()
        if result.rowcount > 0:
            return {"user_id": user_id}
        else:
            return None
    except Exception as e:
        db.session.rollback()
        raise e









# CRUD Role

# CREATE ROLE
def create_role(role_name, description):
 
    try:
        sql = text(""" INSERT INTO roles (role_name, description) VALUES (:role_name, :description) """)
        result = db.session.execute(sql, {'role_name': role_name, 'description': description})
        role_id = db.session.execute(text('SELECT LAST_INSERT_ID();')).fetchone()[0]        
        db.session.commit()
        return role_id
   
    except Exception as e:
        # Rollback the transaction in case of error
        db.session.rollback()
        raise e


# GET ROLE BY ID
def get_role_by_id(role_id):
    try:
        sql = text("SELECT id, role_name, description FROM roles WHERE id = :role_id;")
        result = db.session.execute(sql, {'role_id': role_id})
        role = result.fetchone()
 
        # No need to commit() as no changes are being written to the database
        if role:
            # Convert the result into a dictionary if not None
            role_details = role._asdict()
            return role_details
        else:
            return None
    except Exception as e:
        # Rollback the transaction in case of error
        db.session.rollback()
        raise e


# UPDATE ROLE BY ID
def update_role_by_id(role_id, role_name):
    try:
        sql = text("UPDATE roles SET role_name = :role_name WHERE role_id = :id;")
        result = db.session.execute(sql, {'id': role_id, 'role_name': role_name})
        db.session.commit()
 
        if result.rowcount > 0:
            # Convert the result into a dictionary if not None
            return {"role_id": role_id}
        else:
            return None
 
    except Exception as e:
        # Rollback the transaction in case of error
        db.session.rollback()
        raise e


# DELETE ROLE BY ID
def delete_role_by_id(role_id):
    try:
        sql_delete_role = text("""
        DELETE FROM roles
        WHERE roles.role_id = :id;
        """)
 
        result = db.session.execute(sql_delete_role, {'id': role_id})
 
        db.session.commit()
 
        return {'role_id':role_id}
    except Exception as e:
        # Rollback the transaction in case of error
        db.session.rollback()
        raise e


# GET ALL ROLES
def get_all_roles():
    sql = text('SELECT * FROM roles;')
    result = db.session.execute(sql)
    roles = [dict(row) for row in result]
    return roles


# PAGINATION - SEARCH USERS
def search_users(query_params, page, per_page, logger):
     
    #will not show deleted users
    try:
        base_query = """
            SELECT  
                users.id as user_id,  
                users.username,  
                users.email,  
                users.status,
                user_profiles.first_name,  
                user_profiles.last_name,  
                user_profiles.contact_no,  
                user_profiles.dob,  
                user_profiles.bio,  
                user_profiles.country
            FROM users
            LEFT JOIN user_profiles ON users.id = user_profiles.user_id
            WHERE users.deleted = FALSE  
        """
        query_conditions = []
        query_values = {}
 
        if 'username' in query_params:
            query_conditions.append("users.username LIKE :username")
            query_values['username'] = f"%{query_params['username']}%"
         
        if 'email' in query_params:
            query_conditions.append("users.email LIKE :email")
            query_values['email'] = f"%{query_params['email']}%"
         
        if 'first_name' in query_params:
            query_conditions.append("user_profiles.first_name LIKE :first_name")
            query_values['first_name'] = f"%{query_params['first_name']}%"
         
        if 'last_name' in query_params:
            query_conditions.append("user_profiles.last_name LIKE :last_name")
            query_values['last_name'] = f"%{query_params['last_name']}%"
         
        if 'country' in query_params:
            query_conditions.append("user_profiles.country LIKE :country")
            query_values['country'] = f"%{query_params['country']}%"
 
        if 'age_group' in query_params:
            date_min, date_max = get_age_group(query_params['age_group'])
            if date_min and date_max:
                query_conditions.append("user_profiles.dob BETWEEN :date_min AND :date_max")
                query_values['date_min'] = date_min
                query_values['date_max'] = date_max
 
        if query_conditions:
            base_query += " AND " + " AND ".join(query_conditions)
         
        count_query = f"SELECT COUNT(*) FROM ({base_query}) as count_query"
        total_count = db.session.execute(text(count_query), query_values).scalar()
 
        base_query += " LIMIT :limit OFFSET :offset"
        query_values['limit'] = per_page
        query_values['offset'] = (page - 1) * per_page
 
        result = db.session.execute(text(base_query), query_values).fetchall()
        users = []
        for row in result:
            user = row._asdict()
            if user['dob']:
                age = calculate_age(user['dob'])
                user['age'] = age
                user['age_group'] = get_age_group(age)
            else:
                user['age'] = None
                user['age_group'] = None
            users.append(user)
 
        return {
            "total": total_count,
            "page": page,
            "per_page": per_page,
            "results": users
        }
    except Exception as e:
        logger.error(f"Error searching users: {e}\n{traceback.format_exc()}")
        raise e


# DELETE USER BY ID - DELETE A USER BY ID, MARK AS INACTIVE AND CLEAN USER'S DATA
    def delete_user_by_id(user_id):
        try:
            # Verify user exists in the database
            user_check_sql = text("SELECT id FROM users WHERE id = :user_id")
            user_result = db.session.execute(user_check_sql, {'user_id': user_id}).fetchone()
            if not user_result:
                return None

            # Mark user as inactive and clear details
            sql_update_user = text("""
                UPDATE users
                SET status = '2',
                    username = '',
                    password = ''
                WHERE id = :user_id;
            """)
            db.session.execute(sql_update_user, {'user_id': user_id})

            # Clean up user's profile data
            sql_update_profile = text("""
                UPDATE user_profiles
                SET dob = NULL,
                    bio = '',
                    country = ''
                WHERE user_id = :user_id;
            """)
            db.session.execute(sql_update_profile, {'user_id': user_id})

            # Remove user's images
            sql_delete_user_images = text("""
                DELETE FROM user_image
                WHERE user_id = :user_id;
            """)
            db.session.execute(sql_delete_user_images, {'user_id': user_id})
            db.session.commit()
            return {"user_id": user_id}
        
        except Exception as e:
            db.session.rollback()
            raise e


# # PAGINATION GET USER DETAILS
#     def get_user_details(per_page, offset):
#         try:
#             sql = text("""
#             SELECT users.id, users.username, users.email, user_profiles.first_name, user_profiles.last_name
#             FROM users
#             LEFT JOIN user_profiles ON users.id = user_profiles.user_id
#             LIMIT :per_page OFFSET :offset
#             """)
#             # Execute the SQL Statement by passing in 2 parameters
#             result = db.session.execute(sql, {'per_page': per_page, 'offset': offset})
#             results = result.fetchall()
#             keys = result.keys()  # This fetches the column names
#             list_of_dicts = [dict(zip(keys, row) for row in results]  # Map each key with result
#             return list_of_dicts
#         except Exception as e:
#             # Rollback the transaction in case of error
#             db.session.rollback()
#             raise e