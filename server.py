import secrets
from datetime import datetime

from flask import Flask, render_template, request, session, url_for, redirect

from annexe.python.ldap import Ldap
from annexe.python.private import getAdminLogin

app = Flask(__name__, template_folder='templates')
app.secret_key = secrets.token_hex(16)

DEFAULT_USER, DEFAULT_PASSWORD = getAdminLogin()
LDAP = Ldap('10.22.32.7', 'SINTA', 'LAN', DEFAULT_USER, DEFAULT_PASSWORD)


def init_users_informations():
    all_filters = ["OU=Département Assistance,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
                   "OU=Département Communication,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
                   "OU=Département Finance,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
                   "OU=Département Informatique,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
                   "OU=Département Marketing,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
                   "OU=Département Ressources Humaines,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
                   "OU=Présidence,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
                   "OU=Société SINTA,DC=SINTA,DC=LAN"]
    LDAP.connection()
    users = []
    for f in all_filters:
        entries = LDAP.get_all_users(f)
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
        adm_users = LDAP.getAdmUsers()
        if username not in adm_users and username != 'administrateur':
            return render_template('login.html', error='You are not allowed to connect')
        # check the password and the username for the user in the Adm_group
        if password == DEFAULT_PASSWORD and username == DEFAULT_USER:
            # set the session
            session['username'], session['password'] = username, password
            if remember == 'on':
                session.permanent = True
                app.permanent_session_lifetime = datetime.timedelta(minutes=30)
            # send a message that tell the client is connected
            return redirect(url_for('index'))
        if LDAP.check_password(username, password):
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
    groups = LDAP.get_all_groups()
    users = LDAP.get_all_users("OU=Société SINTA,DC=SINTA,DC=LAN")
    users_names = []
    for user in users:
        users_names.append(user.displayName.value)
    all_organisation_unit = LDAP.get_all_organisation_unit()
    if 'Domain Controllers' in all_organisation_unit:
        all_organisation_unit.remove('Domain Controllers')
    return render_template('adminPanel.html', groups=groups, users=users_names,
                           all_organisation_unit=all_organisation_unit, suggestions=USERS_PROPOSITION)


def admin_connection():
    ldap = Ldap('10.22.32.7', 'SINTA', 'LAN', DEFAULT_USER, DEFAULT_PASSWORD)
    ldap.connection()
    return ldap


@app.route('/adminPanel/addUserToGroup', methods=['GET', 'POST'])
def addUserToGroup():
    if (not session.get('username')) or (not session.get('password')):
        return redirect(url_for('index'))
    if request.method == 'POST':
        user = request.form.getlist('users')
        group = request.form['group']
        LDAP.add_user_to_group(user, group)
        return redirect(url_for('adminPanel'))
    return redirect(url_for('adminPanel'))


@app.route('/adminPanel/deleteGroup', methods=['GET', 'POST'])
def deleteGroup():
    if (not session.get('username')) or (not session.get('password')):
        return redirect(url_for('index'))
    if request.method == 'POST':
        # set to users all users from the form
        group = request.form['group']
        LDAP.delete_group(group)
        return redirect(url_for('adminPanel'))
    return redirect(url_for('adminPanel'))


@app.route('/adminPanel/addGroup', methods=['GET', 'POST'])
def addGroup():
    if (not session.get('username')) or (not session.get('password')):
        return redirect(url_for('index'))
    if request.method == 'POST':
        group = request.form['group']
        organisation_unit = request.form['OU']
        LDAP.create_group(organisation_unit, group)
        return redirect(url_for('adminPanel'))


@app.route('/adminPanel/deleteUserFromGroup', methods=['GET', 'POST'])
def deleteUserFromGroup():
    if (not session.get('username')) or (not session.get('password')):
        return redirect(url_for('index'))
    if request.method == 'POST':
        # set to users all users from the form
        users = request.form.getlist('users')
        group = request.form['group']
        LDAP.delete_users_from_group(users, group)
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
    all_filters = [
        {
            "ASSISTANCE": "OU=Département Assistance,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "COMMUNICATION": "OU=Département Communication,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "FINANCE": "OU=Département Finance,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "INFORMATIQUE": "OU=Département Informatique,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "MARKETING": "OU=Département Marketing,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "RESOURCES HUMAINES": "OU=Département Ressources Humaines,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "PRESIDENCE": "OU=Présidence,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "default": "OU=Société SINTA,DC=SINTA,DC=LAN"
        }
    ]
    # get the value of the filter parameter key from all_filters
    filter_value = []
    if len(request.form.getlist("filtersUsed")) > 0:
        filters = request.form.getlist("filtersUsed")
        # split this string ['["ASSISTANCE","COMMUNICATION"]'] into a list of strings ['ASSISTANCE', 'COMMUNICATION']
        list_filters = filters[0].replace('[', '').replace(']', '').replace('"', '').split(',')
        for f in list_filters:
            filter_value.append(all_filters[0].get(f))

    post_value = request.form.get('searchValue')
    print(filter_value)
    print(filter_value[0] is None)
    if filter_value[0] is None:
        entries = LDAP.search_user(post_value)
    else:
        entries = LDAP.get_users_from_mutliple_organisation(post_value, filter_value)
    if entries is None:
        entries = []
    # Retrieve the necessary information for each compatible user and store it in a list of dicts
    results = []
    for entry in entries:
        print(entry)
        result = {
            'title': entry.title.value,
            'last_name': entry.sn.value,
            'first_name': entry.givenName.value,
        }
        results.append(result)
    return render_template('globalSearch.html', filter=filter_value, users=results, suggestions=USERS_PROPOSITION)


@app.route('/profile')
def profile():
    """
    The function profile() is a route that renders the template profile.html
    :return: The profile.html file is being returned.
    """
    filter_value = request.args.get('user')

    entries = LDAP.search_user(filter_value)
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
