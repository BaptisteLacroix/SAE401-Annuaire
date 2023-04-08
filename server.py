import secrets
from datetime import datetime

from flask import Flask, render_template, request, session, url_for, redirect, jsonify, json, abort
from ldap3 import Entry
from werkzeug import Response

from annexe.python.ldap import Ldap
from annexe.python.private import getAdminLogin

app = Flask(__name__, template_folder='templates')
app.secret_key = secrets.token_hex(16)

DEFAULT_USER, DEFAULT_PASSWORD = getAdminLogin()
LDAP = Ldap('10.22.32.7', 'SINTA', 'LAN', DEFAULT_USER, DEFAULT_PASSWORD)


def init_users_information() -> list[list[str, str]]:
    all_filters = [
        ("OU=Département Assistance,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN", "ASSISTANCE"),
        ("OU=Département Communication,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN", "COMMUNICATION"),
        ("OU=Département Finance,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN", "FINANCE"),
        ("OU=Département Informatique,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN", "INFORMATIQUE"),
        ("OU=Département Marketing,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN", "MARKETING"),
        (
            "OU=Département Ressources Humaines,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "RESSOURCES HUMAINES"),
        ("OU=Présidence,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN", "PRESIDENCE")
    ]
    LDAP.connection()
    users = []
    for f in all_filters:
        entries = LDAP.get_all_users(f[0])
        for entry in entries:
            temp = [entry.displayName.value, entry.birthDate.value, f[1]]
            users.append(temp)
    # use a set to remove duplicates
    users = list(set(map(tuple, users)))
    # convert back to list of lists
    users = [list(user) for user in users]
    return users


USERS_PROPOSITION = init_users_information()


@app.route('/')
@app.route('/index')
def index() -> str:
    """
    The function index() is a route that renders the template index.html
    :return: The index.html file is being returned.
    """
    # show the user profile for that user
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login() -> Response | str:
    """
    The function login() is a route that renders the template login.html
    this function is used to log in the user
    :return: The login.html file is being returned.
    """
    # Check if the user is already logged in
    if session.get('username'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        username: str = request.form['username']
        password: str = request.form['password']
        remember: str = request.form.get('remember')
        # search the user in the Adm_group
        adm_users: list[str] = LDAP.getAdmUsers()
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
            error: str = 'Incorrect username or password'
            return render_template('login.html', error=error)
    else:
        return render_template('login.html')


@app.route('/adminPanel')
def adminPanel() -> Response | str:
    if (not session.get('username')) or (not session.get('password')):
        return redirect(url_for('index'))
    groups: list[str] = LDAP.get_all_groups()
    users: list[Entry] = LDAP.get_all_users("OU=Société SINTA,DC=SINTA,DC=LAN")
    users_names: list[str] = []
    for user in users:
        users_names.append(user.displayName.value)
    all_organisation_unit: list[str] = LDAP.get_all_organisation_unit()
    if 'Domain Controllers' in all_organisation_unit:
        all_organisation_unit.remove('Domain Controllers')
    return render_template('adminPanel.html', groups=groups, users=users_names,
                           all_organisation_unit=all_organisation_unit, suggestions=USERS_PROPOSITION)


def admin_connection() -> Ldap:
    ldap: Ldap = Ldap('10.22.32.7', 'SINTA', 'LAN', DEFAULT_USER, DEFAULT_PASSWORD)
    ldap.connection()
    return ldap


@app.route('/suggestions', methods=['POST'])
def suggestions() -> Response | str:
    if request.method == 'POST':
        search_value: str = request.get_json().get('searchValue')
        # check if there is a number in the search value
        if any(string.isdigit() for string in search_value):
            if session.get('username') and session.get('password'):
                matching_users: list[list[str, str, str]] = search_by_date(search_value)
            else:
                return jsonify([])
        else:
            matching_users: list[list[str, str, str]] = search_by_name(search_value)
        return jsonify(matching_users)


def search_by_name(search_value: str) -> list[list[str, str, str]]:
    # if the search value start with *a so we search for all the users that end with a
    # if the search value end with a* so we search for all the users that start with a
    # if the search value start with a so we search for all the users that contain a
    # if the search value looks like mar* m so we search for all the users that the first_name start with mar and the
    # last_name start with m
    matching_users: list[list[str, str]] = []
    if search_value[0] == '*' and len(search_value) > 1 and search_value[1] != ' ':
        for user in USERS_PROPOSITION:
            # disable the case sensitive
            if user[0].split(' ')[1].lower().endswith(search_value[1:].lower()):
                matching_users.append(user)
    elif search_value[0] == '*' and len(search_value) > 1 and search_value[1] == ' ':
        # search for all users where the last_name start with the search value
        for user in USERS_PROPOSITION:
            # disable the case sensitive
            if user[0].split(' ')[1].lower().startswith(search_value[2:].lower()):
                matching_users.append(user)
    elif search_value[-1] == '*':
        for user in USERS_PROPOSITION:
            if user[0].split(' ')[0].lower().startswith(search_value[:-1].lower()):
                matching_users.append(user)
    elif '*' in search_value:
        for user in USERS_PROPOSITION:
            if user[0].split(' ')[0].lower().startswith(search_value.split('*')[0].lower()) and user[0].split(' ')[1]. \
                    lower().startswith(search_value.split('*')[1].replace(' ', '').lower()):
                matching_users.append(user)
    else:
        for user in USERS_PROPOSITION:
            if search_value.lower() in user[0].lower():
                matching_users.append(user)
    return matching_users


def search_by_date(search_value: str) -> list[list[str, str, str]]:
    # the date of the user looks like 2000/09/30
    # if it's a date, we will search for the birthDate
    # if it's look like <1980 so we search all users born before 1980
    # if it's look like >1980 so we search all users born after 1980
    # if it's look like 1980-1990 so we search all users born between 1980 and 1990
    # if it's look like 10/05/1980 so we search all users born on 10/05/1980
    matching_users: list[list[str, str]] = []
    if search_value[0] == '<':
        print("start with <")
        for user in USERS_PROPOSITION:
            if user[1].split('/')[0] < search_value[1:]:
                matching_users.append(user)
    elif search_value[0] == '>':
        print("start with >")
        for user in USERS_PROPOSITION:
            if user[1].split('/')[0] > search_value[1:]:
                matching_users.append(user)
    elif '-' in search_value:
        print("contains -")
        for user in USERS_PROPOSITION:
            if search_value.split('-')[0] < user[1].split('/')[0] < search_value.split('-')[1]:
                matching_users.append(user)
    elif len(search_value) == 4:
        print("contains year")
        for user in USERS_PROPOSITION:
            if search_value == user[1].split("/")[0]:
                matching_users.append(user)
    else:
        print("contains nothing")
        for user in USERS_PROPOSITION:
            date: str = user[1].split('/')[2] + "/" + user[1].split('/')[1] + "/" + user[1].split('/')[0]
            if date == search_value:
                matching_users.append(user)
    return matching_users


@app.route('/adminPanel/addUserToGroup', methods=['GET', 'POST'])
def addUserToGroup() -> Response | str:
    if (not session.get('username')) or (not session.get('password')):
        return redirect(url_for('index'))
    if request.method == 'POST':
        users: list[str] = request.form.getlist('users')
        group: str = request.form['group']
        LDAP.add_user_to_group(users, group)
        return redirect(url_for('adminPanel'))
    return redirect(url_for('adminPanel'))


@app.route('/adminPanel/deleteGroup', methods=['GET', 'POST'])
def deleteGroup() -> Response | str:
    if (not session.get('username')) or (not session.get('password')):
        return redirect(url_for('index'))
    if request.method == 'POST':
        # set to users all users from the form
        group: str = request.form['group']
        LDAP.delete_group(group)
        return redirect(url_for('adminPanel'))
    return redirect(url_for('adminPanel'))


@app.route('/adminPanel/addGroup', methods=['GET', 'POST'])
def addGroup() -> Response | str:
    if (not session.get('username')) or (not session.get('password')):
        return redirect(url_for('index'))
    if request.method == 'POST':
        group: str = request.form['group']
        organisation_unit: str = request.form['OU']
        LDAP.create_group(organisation_unit, group)
        return redirect(url_for('adminPanel'))


@app.route('/adminPanel/deleteUserFromGroup', methods=['GET', 'POST'])
def deleteUserFromGroup() -> Response | str:
    if (not session.get('username')) or (not session.get('password')):
        return redirect(url_for('index'))
    if request.method == 'POST':
        # set to users all users from the form
        users: list[str] = request.form.getlist('users')
        group: str = request.form['group']
        LDAP.delete_users_from_group(users, group)
        return redirect(url_for('adminPanel'))


@app.route('/logout', methods=['GET', 'POST'])
def logout() -> str:
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
def globalSearch():
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
    if filter_value[0] is None:
        if any(string.isdigit() for string in post_value):
            entries = LDAP.get_multiple_users([user[0] for user in search_by_date(post_value)])
        elif post_value == '*':
            entries = LDAP.get_all_users(all_filters[0].get('default'))
        else:
            entries = LDAP.search_user(post_value)
    else:
        if any(string.isdigit() for string in post_value):
            entries = LDAP.get_mutliple_users_from_multiple_organisation(
                [user[0] for user in search_by_date(post_value)], filter_value)
        else:
            entries = LDAP.get_users_from_mutliple_organisation(post_value, filter_value)
    if entries is None:
        entries = []
    # Retrieve the necessary information for each compatible user and store it in a list of dicts
    results = []
    for entry in entries:
        result = {
            'title': entry.title.value,
            'last_name': entry.sn.value,
            'first_name': entry.givenName.value,
        }
        results.append(result)
    return render_template('globalSearch.html', filter=filter_value, users=results, suggestions=USERS_PROPOSITION)


@app.route('/profile')
def profile() -> str:
    """
    The function profile() is a route that renders the template profile.html
    :return: The profile.html file is being returned.
    """
    filter_value: str = request.args.get('user')

    entries: list[Entry] = LDAP.search_user(filter_value)
    if not entries:
        # If there are no entries, return a 404 error
        abort(404)

    # Get the user profile information
    user_profile: dict[str, str] = {
        'last_name': entries[0].sn.value,
        'first_name': entries[0].givenName.value,
        'mail': entries[0].mail.value,
        'title': entries[0].title.value,
        'telephone': entries[0].telephoneNumber.value,
        'company': entries[0].company.value,
        'department': entries[0].distinguishedName.value.split(',')[1].split('=')[1],
    }

    # Add more user profile information if the user is logged in
    if session.get('username') is not None:
        user_profile.update({
            'co': entries[0].co.value,
            'l': entries[0].l.value,
            'birthDate': entries[0].birthDate.value,
            'age': (datetime.now() - datetime.strptime(entries[0].birthDate.value, "%Y/%m/%d")).days // 365,
            'streetAddress': entries[0].streetAddress.value,
            'postalCode': entries[0].postalCode.value,
            'userPrincipalName': entries[0].userPrincipalName.value,
        })

    # Render the profile template with the user profile information
    return render_template('profile.html', user=user_profile, suggestions=USERS_PROPOSITION)


if __name__ == '__main__':
    app.run(debug=True)
    session.setdefault('username', None)
    session.setdefault('password', None)
