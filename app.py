from flask import Flask, render_template, request, redirect, url_for
import os
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy

# 加载环境变量
load_dotenv()

app = Flask(__name__)

# 配置数据库连接
db_user = os.environ.get('owytpwrkxd@kcatprediction-server')
db_password = os.environ.get('3VIDDvunybB3J$Y3')
db_host = os.environ.get('kcatprediction-server.mysql.database.azure.com')
db_name = os.environ.get('kcatprediction-database')

# 数据库连接字符串
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{db_user}:{db_password}@{db_host}/{db_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# 定义数据模型
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    
    def __repr__(self):
        return f'<Task {self.id}>'

# 确保应用上下文
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    tasks = Task.query.all()
    return render_template('index.html', tasks=tasks)

@app.route('/add', methods=['POST'])
def add():
    task_content = request.form['content']
    new_task = Task(content=task_content)
    
    try:
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('index'))
    except:
        return '添加任务时出现问题'

@app.route('/delete/<int:id>')
def delete(id):
    task_to_delete = Task.query.get_or_404(id)
    
    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect(url_for('index'))
    except:
        return '删除任务时出现问题'

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))