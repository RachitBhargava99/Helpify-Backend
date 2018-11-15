from backend import mail, db
from flask import url_for
from backend.models import Session, User, CheckInSession
from datetime import datetime, timedelta
from sqlalchemy import and_, or_


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender = 'rachitbhargava99@gmail.com', recipients = [user.email])
    msg.body = f'''To reset your password, kindly visit: {url_for('users.reset', token = token, _external = True)}

Kindly ignore this email if you did not make this request'''
    mail.send(msg)

def get_basic_nums_u(auth_token):
    user = User.verify_auth_token(auth_token)
    queue_sessions = Session.query.filter_by(help_status=0).count()
    helper_sessions = User.query.filter_by(isActive=True).count()
    est_wait = queue_sessions * 6 / helper_sessions if helper_sessions != 0 else "No Helper Available"
    num_user_sessions = Session.query.filter_by(requesterID=user.id, help_status=1).count()
    return [queue_sessions, helper_sessions, est_wait, num_user_sessions]

def get_basic_nums_a(auth_token):
    user = User.verify_auth_token(auth_token)
    queue_sessions = Session.query.filter_by(help_status=0).count()
    helper_sessions = User.query.filter_by(isActive=True).count()
    est_wait = queue_sessions * 6 / helper_sessions if helper_sessions != 0 else "No Helper Available"
    current_time = datetime.now()
    time_1_week_back = current_time - timedelta(weeks=1)
    past_24_hours_sessions = Session.query.filter(Session.helperID==user.id, Session.timestamp>time_1_week_back, \
                             Session.help_status==1)
    num_helper_sessions = past_24_hours_sessions.count()
    return [queue_sessions, helper_sessions, est_wait, num_helper_sessions]

def get_help_info(auth_token):
    user = User.verify_auth_token(auth_token)
    helper_sessions = User.query.filter_by(isActive=True).count()
    all_active_sessions = Session.query.filter_by(help_status=0)
    queue_pos = 1
    for session in all_active_sessions:
        if session.requesterID == user.id:
            break
        else:
            queue_pos += 1
    est_wait = (queue_pos-1) * 6 / 1 ##helper_sessions
    return [helper_sessions, int(est_wait), queue_pos]

def get_help_session_info(auth_token):
    user = User.verify_auth_token(auth_token)
    help_session = Session.query.filter(or_(and_(Session.helperID == user.id, Session.help_status == 3), and_(Session.helperID == user.id, Session.help_status == 4))).first()
    requester = User.query.filter_by(id=help_session.requesterID).first()
    requester_name = requester.name
    session_topic = help_session.topic
    return [requester_name, session_topic]

def get_last_session_info(auth_token):
    user = User.verify_auth_token(auth_token)
    last_session = Session.query.filter_by(requesterID=user.id, help_status=1).order_by(Session.id.desc()).first()
    if last_session:
        date = last_session.timestamp
        topic = last_session.topic
        helper_id = last_session.helperID
        helper = User.query.filter_by(id=helper_id).first()
        helper_name = helper.name
        return [date.strftime("%b %d, %Y  %I:%M %p"), topic, helper_name]
    else:
        return ["N/A", "N/A", "N/A"]

def get_last_session_info_a(auth_token):
    user = User.verify_auth_token(auth_token)
    last_session = Session.query.filter_by(helperID=user.id, help_status=1).order_by(Session.id.desc()).first()
    if last_session:
        date = last_session.timestamp
        topic = last_session.topic
        requester_id = last_session.requesterID
        requester = User.query.filter_by(id=requester_id).first()
        requester_name = requester.name
        return [date.strftime("%b %d, %Y  %I:%M %p"), topic, requester_name]
    else:
        return ["N/A", "N/A", "N/A"]

def check_helper_session(auth_token):
    user = User.verify_auth_token(auth_token)
    check_in_session = CheckInSession.query.filter_by(userID=user.id, completion=False).first()
    if check_in_session:
        current_time = datetime.now()
        time_1_hour_back = current_time - timedelta(hours=1)
        if check_in_session.timestamp < time_1_hour_back:
            check_in_session.completion = True
            user.isActive = False
            db.session.commit()

def get_remaining_check_in_time(auth_token):
    user = User.verify_auth_token(auth_token)
    check_in_session = CheckInSession.query.filter_by(userID=user.id, completion=False).first()
    current_time = datetime.now()
    time_1_hour_back = current_time - timedelta(hours=1)
    time_diff = (check_in_session.timestamp - time_1_hour_back)
    return time_diff
