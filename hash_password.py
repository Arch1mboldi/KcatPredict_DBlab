from werkzeug.security import generate_password_hash
password_hash = generate_password_hash('Admin!123', method='scrypt')
print(password_hash)