import secrets
from datetime import timedelta, datetime
from typing import Union

import regex as re
from flask import Flask, render_template, request, session, url_for, redirect, jsonify, abort
from ldap3 import Entry
from werkzeug import Response

from annexe.python.ldap import Ldap
from annexe.python.private import getAdminLogin

app = Flask(__name__, template_folder='templates')
app.secret_key = secrets.token_hex(16)

DEFAULT_USER, DEFAULT_PASSWORD = getAdminLogin()
LDAP = Ldap('10.22.32.7', 'SINTA', 'LAN', DEFAULT_USER, DEFAULT_PASSWORD)


def init_users_information() -> list[list[str, str]]:
    """
    Initialize the list of users and their information.

    Retrieve all users from the LDAP server, and for each user, store their display name, birthdate, and department in
    a list. Remove any duplicate entries from the list and return the resulting list of users and their information.

    This will be used for suggestions when searching a user.

    :return: The list of users and their information, with each user represented as a list containing their display name,
             birthdate, and department.
    :rtype: list[list[str, str]]
    """
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
    users: list[list[str]] = []
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
    Render the home page.

    If the user is logged in, set the 'admin' flag to True and include it in the rendered template.
    If the user is not logged in, set the 'admin' flag to False and include it in the rendered template.

    :return: The HTML content of the rendered template.
    :rtype: str
    """
    # show the user profile for that user
    return render_template('index.html', admin=True if session.get('username') and session.get('password') else False)


@app.route('/login', methods=['GET', 'POST'])
def login() -> Union[Response, str]:
    """
    Handle the login page.

    If the user is already logged in, redirect to the home page.
    If a POST request is received, attempt to authenticate the user with their username and password.
    If authentication is successful, set the session and redirect to the home page.
    If authentication fails, render the login page with an error message.
    If a GET request is received, render the login page.

    :return: A redirect to the home page if authentication is successful, the login page otherwise.
    :rtype: Union[flask.wrappers.Response, str]
    """
    # Check if the user is already logged in
    if session.get('username'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        # check all the fields are filled
        if not request.form['username'] or not request.form['password']:
            return render_template('login.html', error='Please fill all the fields')
        username: str = request.form['username']
        password: str = request.form['password']
        remember: str = request.form.get('remember')
        # search the user in the Adm_group
        adm_users: list[str] = LDAP.get_adm_users()
        if username not in adm_users and username != 'administrateur':
            return render_template('login.html', error='You are not allowed to connect')
        # check the password and the username for the user in the Adm_group
        if password == DEFAULT_PASSWORD and username == DEFAULT_USER:
            # set the session
            session['username'], session['password'] = username, password
            if remember == 'on':
                session.permanent = True
                app.permanent_session_lifetime = timedelta(minutes=30)
            # send a message that tell the client is connected
            return redirect(
                url_for('index', admin=True if session.get('username') and session.get('password') else False))
        if LDAP.check_password(username, password):
            # set the session
            session['username'], session['password'] = username, password
            if remember == 'on':
                session.permanent = True
                app.permanent_session_lifetime = timedelta(minutes=30)
            # send a message that tell the client is connected
            return redirect(
                url_for('index', admin=True if session.get('username') and session.get('password') else False))
        else:
            error: str = 'Incorrect username or password'
            return render_template('login.html', error=error)
    else:
        return render_template('login.html')


@app.route('/adminPanel')
def adminPanel() -> Union[Response, str]:
    """
    Render the admin panel page if the user is authenticated.

    If the user is not authenticated, redirect to the home page.
    Retrieve a list of all groups, all users and all organizational units from LDAP.
    Remove the 'Domain Controllers' unit from the list of organizational units.
    Return a rendered template of the admin panel page, including the retrieved data.

    :return: A rendered template of the admin panel page.
    :rtype: Union[flask.wrappers.Response, str]
    """
    if not is_user_logged_in():
        return redirect(url_for('index'))
    if not LDAP.check_password(session.get('username'), session.get('password')) and \
            session.get('password') != DEFAULT_PASSWORD and session.get('username') != DEFAULT_USER:
        return redirect(url_for('logout'))
    groups: list[str] = LDAP.get_all_groups()
    users: list[Entry] = LDAP.get_all_users("OU=Société SINTA,DC=SINTA,DC=LAN")
    users_names: list[str] = []
    for user in users:
        users_names.append(user.displayName.value)
    all_organisation_unit: list[str] = LDAP.get_all_organisation_unit()
    if 'Domain Controllers' in all_organisation_unit:
        all_organisation_unit.remove('Domain Controllers')
    return get_error_or_success_message('adminPanel.html', groups, users_names, all_organisation_unit,
                                        USERS_PROPOSITION,
                                        True if session.get('username') and session.get('password') else False)


def get_error_or_success_message(link, groups, users_names, all_organisation_unit, suggestions, admin) -> str:
    """
    This function receives a set of parameters, it returns a string based on the value of the query parameters in the
    request object. If the 'success' or 'error' parameters are set, the message returned includes either a success or an
    error message in relation to a particular operation, depending on which parameter is set. Otherwise, it returns a
    string with the default page content.

    :param link: The link of the page to which the function will return the message.
    :type link: str
    :param groups: The groups of the users.
    :type groups: list[str]
    :param users_names: The names of the users.
    :type users_names: list[str]
    :param all_organisation_unit: The list of all organization units.
    :type all_organisation_unit: list[str]
    :param suggestions: The suggestions for the groups or users.
    :type suggestions: list[str]
    :param admin: Whether the current user is an admin or not.
    :type admin: bool
    :return: A string with a success or error message or the default page content.
    :rtype: str
    """
    if request.args.get('success_remove_group'):
        return render_template(link, groups=groups, users=users_names,
                               all_organisation_unit=all_organisation_unit, suggestions=suggestions,
                               success_remove_group=request.args.get('success_remove_group'),
                               admin=admin)
    elif request.args.get('error_remove_group'):
        return render_template(link, groups=groups, users=users_names,
                               all_organisation_unit=all_organisation_unit, suggestions=suggestions,
                               error_remove_group=request.args.get('error_remove_group'),
                               admin=admin)
    elif request.args.get('success_add_group'):
        return render_template(link, groups=groups, users=users_names,
                               all_organisation_unit=all_organisation_unit, suggestions=suggestions,
                               success_add_group=request.args.get('success_add_group'),
                               admin=admin)
    elif request.args.get('error_add_group'):
        return render_template(link, groups=groups, users=users_names,
                               all_organisation_unit=all_organisation_unit, suggestions=suggestions,
                               error_add_group=request.args.get('error_add_group'),
                               admin=admin)
    elif request.args.get('success_add_user_group'):
        return render_template(link, groups=groups, users=users_names,
                               all_organisation_unit=all_organisation_unit, suggestions=suggestions,
                               success_add_user_group=request.args.get('success_add_user_group'),
                               admin=admin)
    elif request.args.get('error_add_user_group'):
        return render_template(link, groups=groups, users=users_names,
                               all_organisation_unit=all_organisation_unit, suggestions=suggestions,
                               error_add_user_group=request.args.get('error_add_user_group'),
                               admin=admin)
    elif request.args.get('success_remove_user_group'):
        return render_template(link, groups=groups, users=users_names,
                               all_organisation_unit=all_organisation_unit, suggestions=suggestions,
                               success_remove_user_group=request.args.get('success_remove_user_group'),
                               admin=admin)
    elif request.args.get('error_remove_user_group'):
        return render_template(link, groups=groups, users=users_names,
                               all_organisation_unit=all_organisation_unit, suggestions=suggestions,
                               error_remove_user_group=request.args.get('error_remove_user_group'),
                               admin=admin)
    elif request.args.get('success_create_user'):
        return render_template(link, groups=groups, users=users_names,
                               all_organisation_unit=all_organisation_unit, suggestions=suggestions,
                               success_create_user=request.args.get('success_create_user'),
                               admin=admin)
    elif request.args.get('error_create_user'):
        return render_template(link, groups=groups, users=users_names,
                               all_organisation_unit=all_organisation_unit, suggestions=suggestions,
                               error_create_user=request.args.get('error_create_user'),
                               admin=admin)
    elif request.args.get('success_remove_user'):
        return render_template(link, groups=groups, users=users_names,
                               all_organisation_unit=all_organisation_unit, suggestions=suggestions,
                               success_remove_user=request.args.get('success_remove_user'),
                               admin=admin)
    elif request.args.get('error_remove_user'):
        return render_template(link, groups=groups, users=users_names,
                               all_organisation_unit=all_organisation_unit, suggestions=suggestions,
                               error_remove_user=request.args.get('error_remove_user'),
                               admin=admin)
    else:
        return render_template(link, groups=groups, users=users_names,
                               all_organisation_unit=all_organisation_unit, suggestions=suggestions,
                               admin=admin)


def admin_connection() -> Ldap:
    """
    Establish an LDAP connection to the server using the default admin credentials.

    :return: A Ldap object with an established connection to the server.
    :rtype: Ldap
    """
    ldap: Ldap = Ldap('10.22.32.7', 'SINTA', 'LAN', DEFAULT_USER, DEFAULT_PASSWORD)
    ldap.connection()
    return ldap


@app.route('/suggestions', methods=['POST'])
def suggestions() -> Union[Response, str]:
    """
    Return a JSON response containing a list of matching users based on the search value.

    If a POST request is received, extract the search value from the JSON request body.
    If the search value contains any digits, perform a search by date.
    Otherwise, perform a search by name.
    If the user is authenticated, include sensitive data in the response.
    Return a JSON response containing the list of matching users.

    :return: A JSON response containing the list of matching users.
    :rtype: Union[flask.wrappers.Response, str]
    """
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
        return jsonify(matching_users)


def search_by_name(search_value: str) -> list[list[str, str, str]]:
    """
    Search for users whose name matches the given search value.

    If the search value starts with '*', search for users whose last name matches the value after the '*'.
    If the search value ends with '*', search for users whose first name matches the value before the '*'.
    If the search value contains '*', search for users whose first and last name match the values before and after the '*'.
    If the search value does not contain '*', search for users whose full name contains the search value.

    :param search_value: The search value to match against user names.
    :type search_value: str
    :return: A list of matching users, where each user is represented as a list of strings [full_name, email, role].
    :rtype: List[List[str]]
    """
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
                # append only the first and the last element from the user
                matching_users.append([user[0], user[2]])
    elif search_value[0] == '*' and len(search_value) > 1 and search_value[1] == ' ':
        # search for all users where the last_name start with the search value
        for user in USERS_PROPOSITION:
            # disable the case sensitive
            if user[0].split(' ')[1].lower().startswith(search_value[2:].lower()):
                matching_users.append([user[0], user[2]])
    elif search_value[-1] == '*':
        for user in USERS_PROPOSITION:
            if user[0].split(' ')[0].lower().startswith(search_value[:-1].lower()):
                matching_users.append([user[0], user[2]])
    elif '*' in search_value:
        for user in USERS_PROPOSITION:
            if user[0].split(' ')[0].lower().startswith(search_value.split('*')[0].lower()) and user[0].split(' ')[1]. \
                    lower().startswith(search_value.split('*')[1].replace(' ', '').lower()):
                matching_users.append([user[0], user[2]])
    else:
        for user in USERS_PROPOSITION:
            if search_value.lower() in user[0].lower():
                matching_users.append([user[0], user[2]])
    return matching_users


def search_by_date(search_value: str) -> list[list[str, str, str]]:
    """
    Search for users by date of birth.

    If search_value is a date in the format "yyyy/mm/dd", return all users with that birth date.
    If search_value is "<yyyy", return all users born before the year yyyy.
    If search_value is ">yyyy", return all users born after the year yyyy.
    If search_value is "yyyy-yyyy", return all users born between the years yyyy and yyyy.
    If search_value is not in any of these formats, return an empty list.

    :param search_value: A search value in one of the formats specified above.
    :type search_value: str
    :return: A list of all matching users, each represented as a list of name, birth date, and email.
    :rtype: List[List[str, str, str]]
    """
    # the date of the user looks like 2000/09/30
    # if it's a date, we will search for the birthDate
    # if it's look like <1980 so we search all users born before 1980
    # if it's look like >1980 so we search all users born after 1980
    # if it's look like 1980-1990 so we search all users born between 1980 and 1990
    # if it's look like 10/05/1980 so we search all users born on 10/05/1980
    matching_users: list[list[str, str]] = []
    if search_value[0] == '<':
        for user in USERS_PROPOSITION:
            if int(user[1].split('/')[0]) <= int(search_value[1:]) and len(search_value[1:]) == 4:
                matching_users.append(user)
    elif search_value[0] == '>':
        for user in USERS_PROPOSITION:
            if int(user[1].split('/')[0]) >= int(search_value[1:]) and len(search_value[1:]) == 4:
                matching_users.append(user)
    elif '-' in search_value:
        for user in USERS_PROPOSITION:
            if search_value.split('-')[0] != '':
                if int(search_value.split('-')[0]) <= int(user[1].split('/')[0]) <= int(search_value.split('-')[1]) \
                        and len(search_value.split('-')[1]) == 4 and len(search_value.split('-')[0]) == 4:
                    matching_users.append(user)
    elif len(search_value) == 4:
        for user in USERS_PROPOSITION:
            if int(search_value) == int(user[1].split("/")[0]):
                matching_users.append(user)
    else:
        for user in USERS_PROPOSITION:
            date: str = user[1].split('/')[2] + "/" + user[1].split('/')[1] + "/" + user[1].split('/')[0]
            if date == search_value:
                matching_users.append(user)
    return matching_users


@app.route('/adminPanel/deleteGroup', methods=['GET', 'POST'])
def deleteGroup() -> Union[Response, str]:
    """
    Handle the deletion of a group from the admin panel.

    If the user is not logged in, redirect to the home page.
    If a POST request is received, attempt to delete the group specified in the form data.
    If deletion is successful, redirect to the admin panel.
    If a GET request is received, redirect to the admin panel.

    :return: A redirect to the admin panel if deletion is successful or a GET request is received,
             a redirect to the home page otherwise.
    :rtype: Union[flask.wrappers.Response, str]
    """
    if not is_user_logged_in():
        return redirect(url_for('index'))
    if not LDAP.check_password(session.get('username'), session.get('password')) and \
            session.get('password') != DEFAULT_PASSWORD and session.get('username') != DEFAULT_USER:
        return redirect(url_for('logout'))
    if request.method == 'POST':
        # set to users all users from the form
        group: str = request.form['group']
        result = LDAP.delete_group(group)
        if result:
            return redirect(url_for('adminPanel', success_remove_group="The group has been successfully removed."))
        return redirect(url_for('adminPanel', error_remove_group="Error while removing the group."))
    return redirect(url_for('adminPanel'))


@app.route('/adminPanel/addGroup', methods=['GET', 'POST'])
def addGroup() -> Union[Response, str]:
    """
    Handle the "add group" page in the admin panel.

    If the user is not logged in, redirect to the home page.
    If a POST request is received, create a new group with the specified name and organisation unit in LDAP,
    then redirect to the admin panel.
    If a GET request is received, render the "add group" page.

    :return: A redirect to the admin panel if a group was successfully created, the "add group" page otherwise.
    :rtype: Union[flask.wrappers.Response, str]
    """
    if not is_user_logged_in():
        return redirect(url_for('index'))
    if not LDAP.check_password(session.get('username'), session.get('password')) and \
            session.get('password') != DEFAULT_PASSWORD and session.get('username') != DEFAULT_USER:
        return redirect(url_for('logout'))
    if request.method == 'POST':
        group: str = request.form['group']
        organisation_unit: str = request.form['OU']
        result = LDAP.create_group(organisation_unit, group)
        if result:
            return redirect(url_for('adminPanel', success_add_group="Group created successfully"))
        return redirect(url_for('adminPanel', error_add_group="Group creation failed"))


@app.route('/adminPanel/addUserToGroup', methods=['GET', 'POST'])
def addUserToGroup() -> Union[Response, str]:
    """
    Handle adding users to a group in the admin panel.

    If the user is not logged in, redirect to the home page.
    If a POST request is received, add the selected users to the specified group in LDAP and redirect to the admin panel.
    If a GET request is received, redirect to the admin panel.

    :return: A redirect to the admin panel if a POST request is received, otherwise a redirect to the admin panel.
    :rtype: Union[flask.wrappers.Response, str]
    """
    if not is_user_logged_in():
        return redirect(url_for('index'))
    if not LDAP.check_password(session.get('username'), session.get('password')) and \
            session.get('password') != DEFAULT_PASSWORD and session.get('username') != DEFAULT_USER:
        return redirect(url_for('logout'))
    if request.method == 'POST':
        users: list[str] = request.form.getlist('users')
        group: str = request.form['group']
        result = LDAP.add_user_to_group(users, group)
        if result:
            return redirect(
                url_for('adminPanel', success_add_user_group="The users were added to the group successfully."))
        return redirect(url_for('adminPanel', error_add_user_group="Error while adding users to the group."))
    return redirect(url_for('adminPanel'))


@app.route('/adminPanel/deleteUserFromGroup', methods=['GET', 'POST'])
def deleteUserFromGroup() -> Union[Response, str]:
    """
    Handle the deletion of users from a group in the admin panel.

    If the user is not logged in, redirect to the home page.
    If a POST request is received, remove the selected users from the specified group.
    After successful deletion, redirect to the admin panel.

    :return: A redirect to the admin panel if deletion is successful, the home page otherwise.
    :rtype: Union[flask.wrappers.Response, str]
    """
    if not is_user_logged_in():
        return redirect(url_for('index'))
    if not LDAP.check_password(session.get('username'), session.get('password')) and \
            session.get('password') != DEFAULT_PASSWORD and session.get('username') != DEFAULT_USER:
        return redirect(url_for('logout'))
    if request.method == 'POST':
        # set to users all users from the form
        users: list[str] = request.form.getlist('users')
        group: str = request.form['group']
        result = LDAP.delete_users_from_group(users, group)
        if result:
            return redirect(url_for('adminPanel', success_remove_user_group="User removed from group"))
        return redirect(url_for('adminPanel', error_remove_user_group="Error removing user from group"))


@app.route('/adminPanel/createUser', methods=['GET', 'POST'])
def createUser() -> Union[Response, str]:
    """
    Handle the "create user" page in the admin panel.

    If the user is not logged in, redirect to the home page.
    If a POST request is received, create a new user with the specified details in LDAP,
    then redirect to the admin panel.
    If a GET request is received, render the "create user" page.

    :return: A redirect to the admin panel if a user was successfully created, the "create user" page otherwise.
    :rtype: Union[flask.wrappers.Response, str]
    """
    global USERS_PROPOSITION
    if not is_user_logged_in():
        return redirect(url_for('index'))
    if not LDAP.check_password(session.get('username'), session.get('password')) and \
            session.get('password') != DEFAULT_PASSWORD and session.get('username') != DEFAULT_USER:
        return redirect(url_for('logout'))
    if request.method == 'POST':
        error_message: str = validate_user_input()
        if error_message:
            return redirect(url_for('adminPanel', error_create_user=error_message))

        # create the user
        result = LDAP.create_user(request.form['first_name'], request.form['last_name'], request.form['email'],
                                  request.form['password'], request.form['birthday'], request.form['tel_prof'],
                                  request.form['tel_perso'], request.form['title'], request.form['adresse'],
                                  request.form['region'], request.form['code_postal'], request.form['ville'],
                                  request.form['pays'], request.form['departement'], request.form['group'])

        if result:
            USERS_PROPOSITION = init_users_information()
            return redirect(url_for('adminPanel', success_create_user="User created successfully"))
        return redirect(url_for('adminPanel', error_create_user="Error while creating user"))
    return redirect(url_for('adminPanel'))


@app.route('/adminPanel/deleteUser', methods=['GET', 'POST'])
def deleteUser() -> Union[Response, str]:
    """
    Handle the deletion of users in the admin panel.

    If the user is not logged in, redirect to the home page.
    If a POST request is received, remove the selected users from LDAP.
    After successful deletion, redirect to the admin panel.

    :return: A redirect to the admin panel if deletion is successful, the home page otherwise.
    :rtype: Union[flask.wrappers.Response, str]
    """
    global USERS_PROPOSITION
    if not is_user_logged_in():
        return redirect(url_for('index'))
    if not LDAP.check_password(session.get('username'), session.get('password')) and \
            session.get('password') != DEFAULT_PASSWORD and session.get('username') != DEFAULT_USER:
        return redirect(url_for('logout'))
    if request.method == 'POST':
        # set to users all users from the form
        user: str = request.form['user']
        result = LDAP.delete_users(user)
        if result:
            USERS_PROPOSITION = init_users_information()
            return redirect(url_for('adminPanel', success_remove_user="User removed successfully"))
        return redirect(url_for('adminPanel', error_remove_user="Error removing user"))


def is_user_logged_in() -> bool:
    """
    Check if a user is logged in by checking the session for a username and password.

    :return: True if the user is logged in, False otherwise.
    :rtype: bool
    """
    return bool(session.get('username') and session.get('password'))


def is_valid_birthday(birthday: str) -> bool:
    """
    Check if the given string is a valid birthday.

    :param birthday: The birthday to check.
    :type birthday: str
    :return: True if the birthday is valid, False otherwise.
    :rtype: bool
    """
    if not re.match("^[0-9]{4}-((0[1-9])|(1[0-2]))-(([0-2][0-9])|(3[0-1]))$", birthday):
        return False
    return True


def is_valid_phone_number(phone_number: str) -> bool:
    """
    Check if the given string is a valid phone number.

    :param phone_number: The phone number to check.
    :type phone_number: str
    :return: True if the phone number is valid, False otherwise.
    :rtype: bool
    """
    if not re.match(r"^[0-9]{10}$", phone_number):
        return False
    return True


def is_valid_postal_code(postal_code: str) -> bool:
    """
    Check if the given string is a valid postal code.

    :param postal_code: The postal code to check.
    :type postal_code: str
    :return: True if the postal code is valid, False otherwise.
    :rtype: bool
    """
    if not re.match(r"^[0-9]{5}$", postal_code):
        return False
    return True


def validate_user_input() -> str:
    """
    Validate user input.

    :return: An error message if the user input is invalid, or an empty string if the input is valid.
    :rtype: str
    """
    required_fields = ['first_name', 'last_name', 'email', 'password', 'birthday', 'tel_prof', 'tel_perso', 'title',
                       'adresse', 'region', 'code_postal', 'ville', 'pays', 'departement', 'group']
    for field in required_fields:
        if not request.form.get(field):
            return f"Veuillez remplir tous les champs {field}"

    if not is_valid_email(request.form.get('email')):
        return "Veuillez entrer une adresse email valide"

    if not is_valid_birthday(request.form.get('birthday')):
        return "Veuillez entrer une date de naissance valide : dd/mm/yyyy"

    if not is_valid_phone_number(request.form.get('tel_prof')):
        return "Veuillez entrer un numéro de téléphone valide"

    if not is_valid_phone_number(request.form.get('tel_perso')):
        return "Veuillez entrer un numéro de téléphone valide"

    if not is_valid_postal_code(request.form.get('code_postal')):
        return "Veuillez entrer un code postal valide"

    if not is_valid_password(request.form.get('password')):
        return "Veuillez entrer un mot de passe valide (8 caractères minimum, 1 majuscule, 1 minuscule, 1 chiffre)"
    return ""


def is_valid_email(email: str) -> bool:
    """
    Check if the given email is valid.

    :param email: The email to check.
    :type email: str
    :return: True if the email is valid, False otherwise.
    :rtype: bool
    """
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))


def is_valid_password(password: str) -> bool:
    """
    Check if the given password is valid.
    :param password: The password to check.
    :return: True if the password is valid, False otherwise.
    """
    return len(password) >= 8 and re.search(r"[a-z]", password) and re.search(r"[A-Z]", password) and re.search(
        r"[0-9]", password)


@app.route('/logout', methods=['GET', 'POST'])
def logout() -> str:
    """
    Handle the logout page.

    If the user is not logged in, render the home page.
    If a POST request is received, log the user out by clearing the session and render the home page.
    If a GET request is received, render the home page.

    :return: The home page with an optional flag indicating whether the user is an admin.
    :rtype: str
    """
    session.pop('username', None)
    session.pop('password', None)
    return render_template('index.html', admin=False)


@app.route('/globalSearch', methods=['GET', 'POST'])
def globalSearch():
    """
    Handles the search functionality for the application. Searches for users in the LDAP database based on the search
    query and filters provided by the user.

    :return: The rendered template 'globalSearch.html' with search results, suggestions, and filter information
             if a search query is provided, otherwise the template without any search results.
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
    if len(request.form.getlist("filtersUsed")) == 0 and request.form.get('searchValue') is None:
        entries = LDAP.get_all_users(all_filters[0].get('default'))
        results = []
        for entry in entries:
            result = {
                'title': entry.title.value,
                'last_name': entry.sn.value,
                'first_name': entry.givenName.value,
            }
            results.append(result)
        return render_template('globalSearch.html', users=results,
                               admin=True if session.get('username') and session.get('password') else False)

    filter_value = get_filter_value(request.form.getlist("filtersUsed"), all_filters)

    post_value = request.form.get('searchValue')
    if filter_value[0] is None:
        if any(string.isdigit() for string in post_value) and is_user_logged_in():
            entries = LDAP.get_multiple_users([user[0] for user in search_by_date(post_value)])
        elif post_value == '*':
            entries = LDAP.get_all_users(all_filters[0].get('default'))
        else:
            entries = LDAP.search_user(post_value)
    else:
        if any(string.isdigit() for string in post_value) and is_user_logged_in():
            entries = LDAP.get_mutliple_users_from_multiple_organisation(
                [user[0] for user in search_by_date(post_value)], filter_value)
        elif post_value == '*':
            entries = LDAP.get_users_from_mutliple_organisation(post_value, filter_value)
        else:
            entries = LDAP.get_users_from_mutliple_organisation(post_value, filter_value)
    if entries is None:
        entries = []
    # Retrieve the necessary information for each compatible user and store it in a list of dicts
    results = create_search_results_list(entries)
    return render_template('globalSearch.html', filter=filter_value, users=results, suggestions=USERS_PROPOSITION
                           , admin=True if session.get('username') and session.get('password') else False)


def get_filter_value(filters_used: list[str], all_filters: list[dict[str, str]]) -> list[str]:
    """
    Convert a list of filters used by the user into a list of their corresponding values.

    The input list `filters_used` is expected to be a list with a single string element. This string should be a JSON-encoded
    list of strings, such as `['["ASSISTANCE","COMMUNICATION"]']`. The function will extract the individual filters from this
    string, convert them into their corresponding values from the input list `all_filters`, and return a list of these values.

    If the input list `filters_used` is empty, the function returns an empty list.

    :param filters_used: A list containing a single string element with the JSON-encoded list of filters used by the user.
    :type filters_used: List[str]
    :param all_filters: A list of dictionaries mapping filter keys to their corresponding values.
    :type all_filters: List[Dict[str, str]]
    :return: A list of filter values corresponding to the filters used by the user.
    :rtype: List[str]
    """
    filter_value = []
    if len(filters_used) > 0:
        # split this string ['["ASSISTANCE","COMMUNICATION"]'] into a list of strings ['ASSISTANCE', 'COMMUNICATION']
        list_filters = filters_used[0].replace('[', '').replace(']', '').replace('"', '').split(',')
        for f in list_filters:
            filter_value.append(all_filters[0].get(f))
    return filter_value


def create_search_results_list(entries: list[Entry]) -> list[dict[str, str]]:
    """
    Given a list of LDAP entries, extract the relevant information and return a list of search results.

    Each search result is a dictionary with the following keys:
    - 'title': the value of the 'title' attribute in the LDAP entry.
    - 'last_name': the value of the 'sn' attribute in the LDAP entry.
    - 'first_name': the value of the 'givenName' attribute in the LDAP entry.

    :param entries: A list of LDAP entries.
    :type entries: List[ldap3.core.entry.Entry]

    :return: A list of search results.
    :rtype: List[Dict[str, str]]
    """
    results = []
    for entry in entries:
        result = {
            'title': entry.title.value,
            'last_name': entry.sn.value,
            'first_name': entry.givenName.value,
        }
        results.append(result)
    return results


@app.route('/profile')
def profile() -> str:
    """
    Display the profile of a user based on the `user` query parameter.

    If the user is not found, return a 404 error.
    If the user is found, retrieve their profile information from the LDAP directory and render the `profile.html`
    template with the user profile information.
    If the user is logged in, additional profile information is displayed.

    :return: The HTML content of the profile page.
    :rtype: str
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
    return render_template('profile.html', user=user_profile, suggestions=USERS_PROPOSITION, admin=True if session.get(
        'username') and session.get('password') else False)


if __name__ == '__main__':
    app.run(debug=True)
    session.setdefault('username', None)
    session.setdefault('password', None)
