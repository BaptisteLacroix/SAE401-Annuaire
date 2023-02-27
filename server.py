import secrets

from flask import Flask, render_template, request, session, url_for, redirect

from annexe.python.ldap import Ldap

app = Flask(__name__, template_folder='templates')


@app.route('/')
@app.route('/index')
def index():
    """
    The function index() is a route that renders the template index.html
    :return: The index.html file is being returned.
    """
    # show the user profile for that user
    return render_template('index.html')


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
        ldap = Ldap('10.22.32.3', 'SINTA', 'LAN', username, password)
        if ldap.connection():
            session['username'] = username
            session['password'] = password
            if remember == 'on':
                session.permanent = True
            else:
                session.permanent = False
            return redirect(url_for('index'))
        else:
            error = 'Incorrect username or password'
            return render_template('login.html', error=error)
    else:
        return render_template('login.html')


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
            "assistance": "OU=Sépartement Assistance,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "communication": "OU=Département Communication,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "finance": "OU=Département Finance,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "informatique": "OU=Département Informatique,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "rh": "OU=Département Ressources Humaines,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
            "presidence": "OU=Présidence,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
        }
    ]
    # get the value of the filter parameter key from all_filters
    filter_value = all_filters[0].get(request.args.get('filter'))
    post_value = request.form.get('searchValue')
    if session.get('username') is None:
        ldap = Ldap('10.22.32.3', 'SINTA', 'LAN', 'administrateur', 'IUT!2023')
        ldap.connection()
        if post_value is not None:
            entries = ldap.search_user(post_value)
        else:
            entries = ldap.get_all_users(filter_value if not None else 'Société SINTA')
    else:
        ldap = Ldap('10.21.32.3', 'SINTA', 'LAN', session.get('username'), session.get('password'))
        ldap.connection()
        if post_value is not None:
            entries = ldap.search_user(post_value)
        else:
            entries = ldap.get_all_users(filter_value if not None else 'Société SINTA')

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

    return render_template('globalSearch.html', filter=filter_value, users=results)


@app.route('/profile')
def profile():
    """
    The function profile() is a route that renders the template profile.html
    :return: The profile.html file is being returned.
    """
    filter_value = request.args.get('user')

    if session.get('username') is None:
        ldap = Ldap('10.22.32.3', 'SINTA', 'LAN', 'administrateur', 'IUT!2023')
        ldap.connection()
        entries = ldap.search_user(filter_value)
        results = []
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
            results.append(result)
    else:
        ldap = Ldap('10.21.32.3', 'SINTA', 'LAN', session.get('username'), session.get('password'))
        ldap.connection()
        entries = ldap.search_user(filter_value)
        results = []
        for entry in entries:
            result = {
                'last_name': entry.sn.value,
                'first_name': entry.givenName.value,
                'mail': entry.mail.value,
                'title': entry.title.value,
                'telephone': entry.telephoneNumber.value,
                'c': entry.c.value,
                'co': entry.co.value,
                'l': entry.l.value,
                'streetAddress': entry.streetAddress.value,
                'postalCode': entry.postalCode.value,
                'userPrincipalName': entry.userPrincipalName.value,

            }
            results.append(result)

    # show the user profile for that user
    return render_template('profile.html', user=results[0])


if __name__ == '__main__':
    app.secret_key = secrets.token_hex(16)
    app.run(debug=True)
    session.setdefault('username', None)
    session.setdefault('password', None)
