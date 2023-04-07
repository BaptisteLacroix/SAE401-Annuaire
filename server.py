import secrets
from datetime import datetime

from flask import Flask, render_template, request, session, url_for, redirect

from annexe.python.ldap import Ldap
from annexe.python.private import getAdminLogin

app = Flask(__name__, template_folder='templates')
app.secret_key = secrets.token_hex(16)


def init_users_informations():
    default_username, default_password = getAdminLogin()
    all_filters = ["OU=Département Assistance,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
                   "OU=Département Communication,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
                   "OU=Département Finance,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
                   "OU=Département Informatique,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
                   "OU=Département Marketing,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
                   "OU=Département Ressources Humaines,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
                   "OU=Présidence,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
                   "OU=Société SINTA,DC=SINTA,DC=LAN"]
    ldap = Ldap('10.22.32.7', 'SINTA', 'LAN', default_username, default_password)
    ldap.connection()
    users = []
    for f in all_filters:
        entries = ldap.get_all_users(f)
        for entry in entries:
            users.append(entry.displayName.value)
    # delete all duplicates
    return list(dict.fromkeys(users))


USERS_PROPOSITION = init_users_informations()


@app.route('/')
@app.route('/index')
def index():
    """
    The function index() is a route that renders the template index.html
    :return: The index.html file is being returned.
    """
    # show the user profile for that user
    return render_template('index.html', suggestions=USERS_PROPOSITION)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    TODO
    :return:
    """
    # Check if the user is already logged in
    if session.get('username'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember')
        # search the user in the Adm_group
        ldap = admin_connection()
        adm_users = ldap.getAdmUsers()
        if username not in adm_users and username != 'administrateur':
            return render_template('login.html', error='You are not allowed to connect')
        # check the password and the username for the user in the Adm_group
        if Ldap('10.22.32.7', 'SINTA', 'LAN', username, password).connection():
            # set the session
            session['username'], session['password'] = username, password
            if remember == 'on':
                session.permanent = True
                app.permanent_session_lifetime = datetime.timedelta(minutes=30)
            # send a message that tell the client is connected
            return redirect(url_for('index'))
        if ldap.check_password(username, password):
            # set the session
            session['username'], session['password'] = username, password
            if remember == 'on':
                session.permanent = True
                app.permanent_session_lifetime = datetime.timedelta(minutes=30)
            # send a message that tell the client is connected
            return redirect(url_for('index'))
        else:
            error = 'Incorrect username or password'
            return render_template('login.html', error=error)
    else:
        return render_template('login.html')


@app.route('/adminPanel')
def adminPanel():
    if (not session.get('username')) or (not session.get('password')):
        return redirect(url_for('index'))

    ldap = admin_connection()

    groups = ldap.get_all_groups()
    users = ldap.get_all_users("OU=Société SINTA,DC=SINTA,DC=LAN")
    users_names = []
    for user in users:
        users_names.append(user.displayName.value)
    all_organisation_unit = ldap.get_all_organisation_unit()
    if 'Domain Controllers' in all_organisation_unit:
        all_organisation_unit.remove('Domain Controllers')
    return render_template('adminPanel.html', groups=groups, users=users_names,
                           all_organisation_unit=all_organisation_unit, suggestions=USERS_PROPOSITION)


def admin_connection():
    default_username, default_password = getAdminLogin()
    ldap = Ldap('10.22.32.7', 'SINTA', 'LAN', default_username, default_password)
    ldap.connection()
    return ldap


@app.route('/adminPanel/addUserToGroup', methods=['GET', 'POST'])
def addUserToGroup():
    if (not session.get('username')) or (not session.get('password')):
        return redirect(url_for('index'))
    ldap = admin_connection()
    if request.method == 'POST':
        user = request.form.getlist('users')
        group = request.form['group']
        ldap.add_user_to_group(user, group)
        return redirect(url_for('adminPanel'))
    return redirect(url_for('adminPanel'))


@app.route('/adminPanel/deleteGroup', methods=['GET', 'POST'])
def deleteGroup():
    if (not session.get('username')) or (not session.get('password')):
        return redirect(url_for('index'))
    ldap = admin_connection()
    if request.method == 'POST':
        # set to users all users from the form
        group = request.form['group']
        ldap.delete_group(group)
        return redirect(url_for('adminPanel'))
    return redirect(url_for('adminPanel'))


@app.route('/adminPanel/addGroup', methods=['GET', 'POST'])
def addGroup():
    if (not session.get('username')) or (not session.get('password')):
        return redirect(url_for('index'))
    ldap = admin_connection()
    if request.method == 'POST':
        group = request.form['group']
        organisation_unit = request.form['OU']
        ldap.create_group(organisation_unit, group)
        return redirect(url_for('adminPanel'))


@app.route('/adminPanel/deleteUserFromGroup', methods=['GET', 'POST'])
def deleteUserFromGroup():
    if (not session.get('username')) or (not session.get('password')):
        return redirect(url_for('index'))
    ldap = admin_connection()
    if request.method == 'POST':
        # set to users all users from the form
        users = request.form.getlist('users')
        group = request.form['group']
        ldap.delete_users_from_group(users, group)
        return redirect(url_for('adminPanel'))


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """
    The function logout() is a route that renders the template index.html
    :return: The index.html file is being returned.
    """
    if not session.get('username'):
        return render_template('index.html')
    print("session logout")
    session.pop('username', None)
    session.pop('password', None)
    return render_template('index.html')


@app.route('/globalSearch', methods=['GET', 'POST'])
def global_search():
    """
    It takes a GET request with a parameter called 'filter' and renders the globalSearch.html template with the filter value
    :return: The globalSearch.html page is being returned.
    """
    default_username, default_password = getAdminLogin()
    all_filters = [
        {
            "assistance": "OU=Département Assistance,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "communication": "OU=Département Communication,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "finance": "OU=Département Finance,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "informatique": "OU=Département Informatique,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "marketing": "OU=Département Marketing,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "rh": "OU=Département Ressources Humaines,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "presidence": "OU=Présidence,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "default": "OU=Société SINTA,DC=SINTA,DC=LAN"
        }
    ]
    # get the value of the filter parameter key from all_filters
    filter_value = all_filters[0].get(request.args.get('filter'))
    post_value = request.form.get('searchValue')
    ldap = admin_connection()
    ldap.connection()
    print(post_value)
    if post_value is not None:
        entries = ldap.search_user(post_value)
    else:
        entries = ldap.get_all_users(all_filters[0].get("default") if filter_value is None else filter_value)

    if entries is None:
        entries = []
    # Retrieve the necessary information for each compatible user and store it in a list of dicts
    results = []
    for entry in entries:
        try:
            result = {
                'title': entry.title.value,
                'last_name': entry.sn.value,
                'first_name': entry.givenName.value,
            }
            results.append(result)
        except AttributeError:
            pass
    return render_template('globalSearch.html', filter=filter_value, users=results, suggestions=USERS_PROPOSITION)


@app.route('/profile')
def profile():
    """
    The function profile() is a route that renders the template profile.html
    :return: The profile.html file is being returned.
    """
    default_username, default_password = getAdminLogin()
    filter_value = request.args.get('user')

    ldap = Ldap('10.22.32.7', 'SINTA', 'LAN',
                default_username if session.get('username') is None else session.get('username'),
                default_password if session.get('password') is None else session.get('password'))
    ldap.connection()
    entries = ldap.search_user(filter_value)
    results = []
    print("ouais ouais oauis")
    if session.get('username') is None:
        for entry in entries:
            result = {
                'last_name': entry.sn.value,
                'first_name': entry.givenName.value,
                'mail': entry.mail.value,
                'title': entry.title.value,
                'telephone': entry.telephoneNumber.value,
                'company': entry.company.value,
                'department': entry.distinguishedName.value.split(',')[1].split('=')[1],
            }
            print(result)
            results.append(result)
            print(results)
    else:
        for entry in entries:
            result = {
                'last_name': entry.sn.value,
                'first_name': entry.givenName.value,
                'mail': entry.mail.value,
                'title': entry.title.value,
                'telephone': entry.telephoneNumber.value,
                'company': entry.company.value,
                'department': entry.distinguishedName.value.split(',')[1].split('=')[1],
                'co': entry.co.value,
                'l': entry.l.value,
                'birthDate': entry.birthDate.value,
                'age': (datetime.now() - datetime.strptime(entry.birthDate.value, "%Y/%m/%d")).days // 365,
                'streetAddress': entry.streetAddress.value,
                'postalCode': entry.postalCode.value,
                'userPrincipalName': entry.userPrincipalName.value,
            }
            results.append(result)
    # show the user profile for that user
    print(results[0])
    return render_template('profile.html', user=results[0], suggestions=USERS_PROPOSITION)


if __name__ == '__main__':
    app.run(debug=True)
    session.setdefault('username', None)
    session.setdefault('password', None)
