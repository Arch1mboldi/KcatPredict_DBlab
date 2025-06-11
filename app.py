from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Zjzlmk200513@127.0.0.1:3306/enzyme_predictor'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# 模型定义
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'biochemist', 'ml_experimenter',  'admin'
    invite_code = db.Column(db.String(20), unique=True, nullable=True)
    registered_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    registration_time = db.Column(db.DateTime, default=datetime.utcnow)
    invite_uses = db.Column(db.Integer, default=0)

    # 关系
    invited_users = db.relationship('User', backref=db.backref('inviter', remote_side=[id]))
    wet_experiments = db.relationship('WetExperiment', backref='experimenter', lazy=True)
    ml_experiments = db.relationship('MLExperiment', backref='experimenter', lazy=True)
    ml_validations = db.relationship('MLValidation', backref='experimenter', lazy=True)

    def is_admin(self):
        return self.role == 'admin'

class WetExperiment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    experiment_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    enzyme_class = db.Column(db.String(50), nullable=False)
    substrate_name = db.Column(db.String(100), nullable=False)
    kcat_value = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class MLExperiment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    training_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    dataset_seed = db.Column(db.Integer, nullable=False)
    rmse = db.Column(db.Float, nullable=False)
    pearson_r = db.Column(db.Float, nullable=False)
    r2 = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    source_code = db.Column(db.String(255), nullable=False)

    validations = db.relationship('MLValidation', backref='ml_experiment', lazy=True)


class MLValidation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prediction_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    score = db.Column(db.Float, nullable=False)
    ml_experiment_id = db.Column(db.Integer, db.ForeignKey('ml_experiment.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# 登录管理器用户加载回调
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# 自定义密码验证函数
def validate_password(password):
    # 密码必须至少包含两种字符类型
    uppercase = re.search(r'[A-Z]', password)
    lowercase = re.search(r'[a-z]', password)
    digit = re.search(r'\d', password)
    special = re.search(r'[!@#$%^&*(),.?":{}|<>]', password)

    types = 0
    if uppercase:
        types += 1
    if lowercase:
        types += 1
    if digit:
        types += 1
    if special:
        types += 1

    return types >= 2


# 生成邀请码
def generate_invite_code():
    import string
    import random
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for i in range(10))


# 初始化数据库
def init_db():
    from sqlalchemy import text

    with app.app_context():
        # 创建所有表
        db.create_all()

        # 创建视图
        try:
            with db.engine.connect() as connection:
                connection.execute(text('''
                    CREATE OR REPLACE VIEW enzyme_data_view AS
                    SELECT 
                        we.id,
                        we.experiment_time,
                        we.enzyme_class,
                        we.substrate_name,
                        we.kcat_value,
                        u.username as experimenter
                    FROM wet_experiment we
                    JOIN user u ON we.user_id = u.id
                '''))
                connection.commit()
        except Exception as e:
            print(f"Error creating view: {e}")
            raise

        # 创建存储过程
        try:
            with db.engine.connect() as connection:
                # 先删除现有存储过程
                connection.execute(text('DROP PROCEDURE IF EXISTS GetMLExperimentScores;'))
                connection.commit()

                # 创建存储过程
                connection.execute(text('''
                    CREATE PROCEDURE GetMLExperimentScores(IN experiment_id INT)
                    BEGIN
                        SELECT 
                            mlv.id,
                            mlv.prediction_time,
                            mlv.score,
                            u.username as validator
                        FROM ml_validation mlv
                        JOIN user u ON mlv.user_id = u.id
                        WHERE mlv.ml_experiment_id = experiment_id
                        ORDER BY mlv.prediction_time DESC;
                    END
                '''))
                connection.commit()
        except Exception as e:
            print(f"Error creating procedure: {e}")
            raise

            # 创建触发器
            #try:
             #   with db.engine.connect() as connection:
              #      # 先删除现有触发器
               #     connection.execute(text('DROP TRIGGER IF EXISTS after_user_insert;'))
                #    connection.commit()
#
 #                   # 创建触发器
  #                  connection.execute(text('''
   #                             CREATE TRIGGER after_user_insert
    #                            AFTER INSERT ON user
     #                           FOR EACH ROW
      #                          BEGIN
       #                             IF NEW.role IN ('biochemist', 'ml_experimenter') AND NEW.registered_by IS NOT NULL THEN
        #                                UPDATE user
         #                               SET invite_uses = invite_uses + 1
          #                              WHERE id = NEW.registered_by;
           #                         END IF;
            #                    END
             #               '''))
              #      connection.commit()
            #except Exception as e:
             #   print(f"Error creating trigger: {e}")
              #  raise

        # 创建索引 - 先检查索引是否存在
        with db.engine.connect() as connection:
            # 检查idx_enzyme_class索引是否存在
            result = connection.execute(text('''
                SELECT COUNT(*) 
                FROM information_schema.statistics 
                WHERE table_schema = DATABASE() 
                AND table_name = 'wet_experiment' 
                AND index_name = 'idx_enzyme_class'
            '''))
            index_exists = result.scalar() > 0

            if not index_exists:
                connection.execute(text('CREATE INDEX idx_enzyme_class ON wet_experiment (enzyme_class);'))
                connection.commit()
                print("Index idx_enzyme_class created")
            else:
                print("Index idx_enzyme_class already exists")

        # 创建索引 - 先检查索引是否存在
        with db.engine.connect() as connection:
            # 检查idx_username索引是否存在
            result = connection.execute(text('''
                SELECT COUNT(*) 
                FROM information_schema.statistics 
                WHERE table_schema = DATABASE() 
                AND table_name = 'user' 
                AND index_name = 'idx_username'
            '''))
            index_exists = result.scalar() > 0

            if not index_exists:
                connection.execute(text('CREATE INDEX idx_username ON user (username);'))
                connection.commit()
                print("Index idx_username created")
            else:
                print("Index idx_username already exists")

        print("Database initialized successfully!")
        # 插入测试用户

# 路由
@app.route('/')
def index():
    # 获取酶数据
    enzyme_data = WetExperiment.query.all()

    # 获取机器学习实验及其评分
    ml_experiments = MLExperiment.query.all()

    # 计算每个实验的平均分数
    experiment_scores = {}
    for experiment in ml_experiments:
        validations = experiment.validations
        if validations:
            avg_score = sum(v.score for v in validations) / len(validations)
            experiment_scores[experiment.id] = {
                'avg_score': avg_score,
                'validation_count': len(validations)
            }
        else:
            experiment_scores[experiment.id] = {
                'avg_score': 0,
                'validation_count': 0
            }

    return render_template('index.html', enzyme_data=enzyme_data, ml_experiments=ml_experiments,
                           experiment_scores=experiment_scores)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        invite_code = request.form.get('invite_code')
        role = request.form.get('role')

        print(f"Received form data: username={username}, password={password}, invite_code={invite_code}, role={role}")

        if not all([username, password, role]):
            flash('请填写所有必填字段', 'danger')
            return redirect(url_for('register'))

        # 验证用户名长度
        if not (3 <= len(username) <= 20):
            flash('用户名长度必须在3-20个字符之间', 'danger')
            return redirect(url_for('register'))

        # 验证密码复杂度
        if not validate_password(password):
            flash('密码必须包含至少两种字符类型（大写字母、小写字母、数字、特殊字符）', 'danger')
            return redirect(url_for('register'))

        # 检查用户名是否已存在
        if User.query.filter_by(username=username).first():
            flash('用户名已存在', 'danger')
            return redirect(url_for('register'))

        # 检查邀请码
        inviter = User.query.filter_by(invite_code=invite_code).first()
        if not inviter:
            flash('无效的邀请码', 'danger')
            return redirect(url_for('register'))

        # 检查邀请码使用次数
        if inviter.invite_uses >= 3:
            flash('此邀请码已达到最大使用次数', 'danger')
            return redirect(url_for('register'))

        # 创建新用户
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password, method='scrypt'),
            role=role,
            invite_code=generate_invite_code(),
            registered_by=inviter.id
        )

        db.session.add(new_user)
        db.session.commit()

        # 手动更新invite_uses字段
        if role in ('biochemist', 'ml_experimenter'):
            inviter.invite_uses += 1
            db.session.commit()

        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('登录成功', 'success')
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('已退出登录', 'info')
    return redirect(url_for('index'))


@app.route('/enzyme_entry', methods=['GET', 'POST'])
@login_required
def enzyme_entry():
    if current_user.role == 'ml_experimenter' or current_user.role == 'admin':
        flash('只有生化实验人员可以访问此页面', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        experiment_time = datetime.strptime(request.form['experiment_time'], '%Y-%m-%dT%H:%M')
        enzyme_class = request.form['ec_number']
        substrate_name = request.form['substrate_name']
        kcat_value = float(request.form['kcat_value'])

        experiment = WetExperiment(
            experiment_time=experiment_time,
            enzyme_class=enzyme_class,
            substrate_name=substrate_name,
            kcat_value=kcat_value,
            user_id=current_user.id
        )

        db.session.add(experiment)
        db.session.commit()

        flash('酶数据录入成功', 'success')
        return redirect(url_for('enzyme_entry'))

    return render_template('enzyme_entry.html')


@app.route('/ml_entry', methods=['GET', 'POST'])
@login_required
def ml_entry():
    if current_user.role == 'biochemist' or current_user.role == 'admin':
        flash('只有机器学习实验人员可以访问此页面', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'pretrain':
            # 处理模型预训练表单
            training_time = datetime.strptime(request.form['training_time'], '%Y-%m-%dT%H:%M')
            dataset_seed = int(request.form['dataset_seed'])
            rmse = float(request.form['rmse'])
            pearson_r = float(request.form['pearson_r'])
            r2 = float(request.form['r2'])

            # 处理文件上传
            file = request.files['source_code']
            if file and file.filename.endswith('.zip'):
                filename = f"experiment_{datetime.now().strftime('%Y%m%d%H%M%S')}.zip"
                file.save(os.path.join('uploads', filename))
            else:
                flash('请上传有效的.zip文件', 'danger')
                return redirect(url_for('ml_entry'))

            experiment = MLExperiment(
                training_time=training_time,
                dataset_seed=dataset_seed,
                rmse=rmse,
                pearson_r=pearson_r,
                r2=r2,
                user_id=current_user.id,
                source_code=filename
            )

            db.session.add(experiment)
            db.session.commit()

            flash('模型预训练数据提交成功', 'success')
            return redirect(url_for('ml_entry'))

        elif action == 'validate':
            # 处理模型验证表单
            prediction_time = datetime.strptime(request.form['prediction_time'], '%Y-%m-%dT%H:%M')
            score = float(request.form['score'])
            experiment_id = int(request.form['experiment_id'])

            validation = MLValidation(
                prediction_time=prediction_time,
                score=score,
                ml_experiment_id=experiment_id,
                user_id=current_user.id
            )

            db.session.add(validation)
            db.session.commit()

            flash('模型验证数据提交成功', 'success')
            return redirect(url_for('ml_entry'))

    # 获取所有可验证的实验
    experiments = MLExperiment.query.all()

    return render_template('ml_entry.html', experiments=experiments)


@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('只有管理员可以访问此页面', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')

        if action == 'delete' and user_id:
            user = User.query.get(user_id)
            if user and user.role != 'admin':  # 不能删除管理员
                db.session.delete(user)
                db.session.commit()
                flash('用户已删除', 'success')
            else:
                flash('无法删除该用户', 'danger')

        elif action == 'add':
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']

            # 验证用户名长度
            if not (3 <= len(username) <= 20):
                flash('用户名长度必须在3-20个字符之间', 'danger')
                return redirect(url_for('admin_users'))

            # 验证密码复杂度
            if not validate_password(password):
                flash('密码必须包含至少两种字符类型（大写字母、小写字母、数字、特殊字符）', 'danger')
                return redirect(url_for('admin_users'))

            # 检查用户名是否已存在
            if User.query.filter_by(username=username).first():
                flash('用户名已存在', 'danger')
                return redirect(url_for('admin_users'))

            # 创建新用户
            new_user = User(
                username=username,
                password_hash=generate_password_hash(password, method='scrypt'),  # 关键修改
                role=role,
                invite_code=generate_invite_code() if role != 'admin' else None
            )

            db.session.add(new_user)
            db.session.commit()

            flash('用户已添加', 'success')

    # 获取所有用户
    users = User.query.all()
    stats = {
        'total_users': User.query.count(),
        'biochemists': User.query.filter_by(role='biochemist').count(),
        'ml_experimenters': User.query.filter_by(role='ml_experimenter').count(),
        'admins': User.query.filter_by(role='admin').count(),
    }

    return render_template('admin_users.html', users=users, stats=stats)


@app.route('/download/<filename>')
@login_required
def download(filename):
    # 确保用户只能下载允许的文件
    if current_user.role == 'ml_experimenter' or current_user.role == 'admin':
        return send_from_directory('uploads', filename)
    else:
        flash('权限不足', 'danger')
        return redirect(url_for('index'))


if __name__ == '__main__':
    # 创建上传文件夹
    if not os.path.exists('uploads'):
        os.makedirs('uploads')

    # 初始化数据库
    init_db()

    app.run(debug=True)