from flask import abort, jsonify, request, redirect, send_file, url_for
from flask_login import (current_user, logout_user,
                         login_user, user_logged_in, user_logged_out)
from flask_principal import AnonymousIdentity, Identity,  identity_changed
from myapp.app import app,login_manager
import time


app_start_time = time.time()
 

@app.errorhandler(404)
def page_not_found(e):
    return send_file('build/index.html')

@app.route('/adm/logout', methods=['GET', 'POST'])
def logout_admin():
    logout_user()
    return redirect(url_for('login_admin'))   

@app.before_request
def limit_swagger_access():
    if request.path == '/swagger.json' or request.path.startswith('/doc'):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)  
    

@app.before_request
def start_request():

    app.logger.info('Start request %s', request.url)

@app.after_request
def end_request(response):

    app.logger.info('End request %s with status %s', request.url, response.status)
    return response

@app.errorhandler(500)
def server_error(e):

    app.logger.error('Server error: %s', e)
    return 'An internal error occurred.', 500

@login_manager.unauthorized_handler
def unauthorized():
    return {'code': 400, 'message': 'you must login', 'data': []}, 200

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@user_logged_in.connect_via(app)
def on_user_logged_in(sender, user):
    identity_changed.send(sender, identity=Identity(user.id))


@user_logged_out.connect_via(app)
def on_user_logged_out(sender, user):
    identity_changed.send(sender, identity=AnonymousIdentity())

@login_manager.request_loader
def load_user_from_request(request):
    # try to login using the api_key url arg
    api_key = request.args.get('api_key')
    if api_key:
        user = User.query.filter_by(api_key=api_key).first()
        if user:
            return user    # finally, return None if both methods did not login the user
    return None

@app.errorhandler(403)
def forbidden(e):
    return {"message": "You do not have permission to access this resource."}, 403





