from flask import Blueprint, request
from backend.models import User, Session, CheckInSession
from backend import db, bcrypt
import json
from backend.users.utils import send_reset_email, get_basic_nums_u, get_help_info, get_last_session_info,\
    get_basic_nums_a, get_help_session_info, get_last_session_info_a, check_helper_session, get_remaining_check_in_time
from datetime import datetime, timedelta
from sqlalchemy import and_, or_

users = Blueprint('users', __name__)


@users.route('/login', methods=['GET', 'POST'])
def login():
    request_json = request.get_json()
    email = request_json['email']
    password = request_json['password']
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        final_dict = {
            'id': user.id,
            'auth_token': user.get_auth_token(),
            'name': user.name,
            'email': user.email,
            'gt_id': user.gt_id,
            'isAdmin': user.isAdmin,
            'isMaster': user.isMaster,
            'status': 1
        }
        return json.dumps(final_dict)
    else:
        final_dict = {
            'status': 0,
            'error': "The provided combination of email and password is incorrect."
        }
        return json.dumps(final_dict)


@users.route('/register', methods=['GET', 'POST'])
def normal_register():
    request_json = request.get_json()
    if User.query.filter_by(email=request_json['email']).first():
        return json.dumps({'status': 0, 'output': User.query.filter_by(email=request_json['email']).first().email,
                          'error': "User Already Exists"})
    elif User.query.filter_by(gt_id=request_json['gt_id']).first():
        return json.dumps({'status': 0, 'error': "The provided GeorgiaTech ID is already registered."})
    email = request_json['email']
    hashed_pwd = bcrypt.generate_password_hash(request_json['password']).decode('utf-8')
    name = request_json['name']
    gt_id = request_json['gt_id']
    # noinspection PyArgumentList
    user = User(email=email, password=hashed_pwd, name=name, gt_id=gt_id, isAdmin=False)
    db.session.add(user)
    db.session.commit()
    return json.dumps({'id': user.id, 'status': 1})


@users.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    request_json = request.get_json()
    if User.query.filter_by(email=request_json['email']).first():
        return json.dumps({'status': 0, 'output': User.query.filter_by(email=request_json['email']).first().email},
                          error="User Already Exists")
    if not admin_checker(request_json['gt_id']):
        return json.dump({'status': 0, 'output': User.query.filter_by(email=request_json['email']).first().email},
                          error="Admin Registration Not Authorized")
    email = request_json['email']
    hashed_pwd = bcrypt.generate_password_hash(request_json['password']).decode('utf-8')
    name = request_json['name']
    gt_id = request_json['gt_id']
    user = User(email=email, password=hashed_pwd, name=name, gt_id=gt_id, isAdmin=True)
    db.session.add(user)
    db.session.commit()
    return json.dumps({'id': user.id, 'status': 1})


@users.route('/admin/add', methods=['GET', 'POST'])
def admin_add():
    request_json = request.get_json()
    user = User.query.filter_by(gt_id=request_json['gt_id']).first()
    user.isAdmin = True
    db.session.commit()
    return json.dumps({'status': 1})


@users.route('/verify_registration', methods=['GET', 'POST'])
def verify_registration():
    request_json = request.get_json()
    gt_id = request_json['gt_id']
    email = request_json['email']
    status = 1
    user = User.query.filter_by(gt_id=gt_id).first()
    if user:
        status = 0
        error = f"GeorgiaTech ID {gt_id} has already been taken."
    if not (gt_id > 900000000 and gt_id < 1000000000):
        status = 0
        error = f"The entered GeorgiaTech ID is incorrect. Please try again."
    user2 = User.query.filter_by(email=email).first()
    if user2:
        status = 0
        error = f"Email {email} has already been taken."
    if status == 1:
        return json.dumps({"status": status})
    else:
        return json.dumps({"status": status, "error": error})


@users.route('/password/request_reset', methods=['GET', 'POST'])
def request_reset_password():
    request_json = request.get_json()
    user = User.query.filter_by(email=request_json['email']).first()
    if user:
        send_reset_email(user)
        return json.dumps({'status': 1})
    else:
        return json.dumps({'status': 0, 'error': "User Not Found"})


@users.route('/backend/password/verify_token', methods=['GET', 'POST'])
def verify_reset_token():
    request_json = request.get_json()
    user = User.verify_reset_token(request_json['token'])
    if user is None:
        return json.dumps({'status': 0, 'error': "Sorry, the link is invalid or has expired. Please submit password reset request again."})
    else:
        return json.dumps({'status': 1})


@users.route('/backend/password/reset', methods=['GET', 'POST'])
def reset_password():
    request_json = request.get_json()
    user = User.verify_reset_token(token)
    if user is None:
        return json.dumps({'status': 0,
                           'error': "Sorry, the link is invalid or has expired. Please submit password reset request again."})
    else:
        hashed_pwd = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_pwd
        db.session.commit()
        return json.dumps({'status': 1})

@users.route('/dashboard', methods=['GET', 'POST'])
def get_dashboard_info():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(request_json['auth_token'])
    if user is None:
        return json.dumps({'status': 0,
                           'error': "Session expired. Please login again."})
    else:
        if user.isAdmin:
            num_session = get_basic_nums_a(auth_token)

            check_helper_session(auth_token)

            active_status = user.isActive

            if active_status or Session.query.filter(or_(and_(Session.helperID == user.id, Session.help_status == 3), and_(Session.helperID == user.id, Session.help_status == 4))).first():
                recur = True
                while (recur):
                    check_session = Session.query.filter(or_(and_(Session.helperID == user.id, Session.help_status == 4), and_(Session.helperID == user.id, Session.help_status == 3), Session.help_status == 0))
                    new_session = check_session.first()
                    if new_session:
                        new_session.helperID = user.id
                        current_time = datetime.now()
                        if new_session.help_status == 0:
                            new_session.help_status = 3
                            new_session.timestamp = current_time
                            recur = False
                        elif new_session.help_status == 3:
                            time_30_seconds_back = current_time - timedelta(seconds=30)
                            if new_session.timestamp < time_30_seconds_back:
                                new_session.help_status = 4
                                new_session.timestamp = current_time
                            recur = False
                        elif new_session.help_status == 4:
                            time_10_minutes_back = current_time - timedelta(minutes=10)
                            if new_session.timestamp < time_10_minutes_back:
                                new_session.help_status = 1
                                new_session.timestamp = current_time
                                if not active_status:
                                    recur = False

                                    last_session = get_last_session_info_a(auth_token)

                                    return json.dumps({
                                        'status': 1,
                                        'queue_length': num_session[0],
                                        'helpers_active': num_session[1],
                                        'estimated_wait_time': num_session[2],
                                        'sessions_today': num_session[3],
                                        'last_session_date': last_session[0],
                                        'last_session_topic': last_session[1],
                                        'last_session_requester': last_session[2],
                                        'user': "Admin",
                                        'activity_status': False
                                    })
                            else:
                                recur = False
                        db.session.commit()
                    else:
                        recur = False

                        last_session = get_last_session_info_a(auth_token)

                        time_remaining = get_remaining_check_in_time(auth_token) if active_status else 0
                        seconds_remaining = time_remaining.seconds if time_remaining != 0 else 0
                        minutes_remaining = seconds_remaining // 60

                        return json.dumps({
                            'status': 1,
                            'queue_length': num_session[0],
                            'helpers_active': num_session[1],
                            'estimated_wait_time': num_session[2],
                            'sessions_today': num_session[3],
                            'minutes_remaining': minutes_remaining,
                            'requester_name': "No Requester Around",
                            'topic': "No Requester Around",
                            'help_time_left': 30,
                            'last_session_date': str(last_session[0]),
                            'last_session_topic': last_session[1],
                            'last_session_requester': last_session[2],
                            'user': "Admin",
                            'activity_status': True,
                            'help_status': 3
                        })
                help_session = get_help_session_info(auth_token)

                last_session = get_last_session_info_a(auth_token)

                time_remaining = get_remaining_check_in_time(auth_token) if active_status else 0
                seconds_remaining = time_remaining.seconds if time_remaining != 0 else 0
                minutes_remaining = seconds_remaining // 60

                return json.dumps({'status': 1,
                                   'help_status': new_session.help_status,
                                   'queue_length':  num_session[0],
                                   'helpers_active': num_session[1],
                                   'estimated_wait_time': num_session[2],
                                   'sessions_today': num_session[3],
                                   'minutes_remaining': minutes_remaining,
                                   'requester_name': help_session[0],
                                   'topic': help_session[1],
                                   'help_time_left': 30 if new_session.help_status == 3 else 600,
                                   'last_session_date': last_session[0],
                                   'last_session_topic': last_session[1],
                                   'last_session_requester': last_session[2],
                                   'user': "Admin",
                                   'activity_status': True})
            else:
                last_session = get_last_session_info_a(auth_token)

                return json.dumps({'status': 1,
                                   'queue_length':  num_session[0],
                                   'helpers_active': num_session[1],
                                   'estimated_wait_time': num_session[2],
                                   'sessions_today': num_session[3],
                                   'last_session_date': last_session[0],
                                   'last_session_topic': last_session[1],
                                   'last_session_requester': last_session[2],
                                   'user': "Admin",
                                   'activity_status': False})

        else:
            num_sessions = get_basic_nums_u(auth_token)

            hasSession = Session.query.filter_by(requesterID=user.id, help_status=0).first()
            if hasSession:
                request_help = get_help_info(auth_token) + [True]
            else:
                request_help = ["Help Not Requested", "Help Not Requested", "Help Not Requested"] + [False]

            last_session = get_last_session_info(auth_token)

            return json.dumps({'status': 1,
                               'queue_length': num_sessions[0],
                               'helpers_active': num_sessions[1],
                               'estimated_wait_time': num_sessions[2],
                               'num_total_sessions': num_sessions[3],
                               'current_helpers_active': request_help[0],
                               'current_wait_time': request_help[1],
                               'current_queue_pos': request_help[2],
                               'help_requested': request_help[3],
                               'last_session_date': last_session[0],
                               'last_session_topic': last_session[1],
                               'last_session_helper': last_session[2],
                               'user': "Normal"})


@users.route('/check_in', methods=['GET', 'POST'])
def check_in():
    request_json = request.get_json()
    user = User.verify_auth_token(request_json['auth_token'])
    if not user:
        return json.dumps({
            'status': 0,
            'error': "User could not be authenticated. Please log in again."
        })
    else:
        check_in_session = CheckInSession(userID=user.id)
        db.session.add(check_in_session)
        user.isActive = True
        db.session.commit()
        return json.dumps({
            'status': 1
        })


@users.route('/users/helpers', methods=['GET', 'POST'])
def get_session_data_a():
    request_json = request.get_json()
    auth_token = request_json['auth_token']
    user = User.verify_auth_token(auth_token)
    if not user:
        return json.dumps({'status': 0, 'error': "Authentication Failed"})
    else:
        helpers = User.query.filter_by(isActive=True)
        final = {"rows": []}
        count = 1
        for helper in helpers:
            final["rows"].append({
                "id": count,
                "name": helper.name,
            })
            count += 1
        return json.dumps({'status': 1, 'data': final["rows"], 'user_type': "Admin" if user.isAdmin else "Normal"})


@users.route('/test', methods=['GET'])
def test():
    return "Hello World"