import secrets

from flask import Flask, render_template, request, session, url_for, redirect, g

from annexe.python.ldap import Ldap
from annexe.python.login import Login

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


@app.before_request
def before_request():
    g.user = None
    try:
        g.login
    except AttributeError:
        # Create a new instance of the Login class for each request
        g.login = Login()


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
        if g.login.connect(username, password):
            session['username'] = username
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
    session.pop('username', None)
    g.login.logout()
    g.pop('login', None)
    return render_template('index.html')


@app.route('/globalSearch')
def global_search():
    """
    It takes a GET request with a parameter called 'filter' and renders the globalSearch.html template with the filter value
    :return: The globalSearch.html page is being returned.
    """
    # show the user profile for that user
    filter_value = request.args.get('filter')

    if g.login.ldap is None:
        ldap = Ldap('10.22.32.3', 'SINTA', 'LAN', 'administrateur', 'IUT!2023')
        ldap.connection()
        entries = ldap.get_all_users('Société SINTA')
    else:
        ldap = g.login.ldap
        entries = ldap.get_all_users('Société SINTA')

    # Retrieve the necessary information for each compatible user and store it in a list of dicts
    results = []
    print(entries[0].title.value)
    for entry in entries:
        result = {
            'title': entry.title.value,
            'last_name': entry.sn.value,
            'first_name': entry.givenName.value,
        }
        results.append(result)

    print(results)

    return render_template('globalSearch.html', filter=filter_value, users=results)


@app.route('/profile')
def profile():
    """
    The function profile() is a route that renders the template profile.html
    :return: The profile.html file is being returned.
    """
    # show the user profile for that user
    return render_template('profile.html')


if __name__ == '__main__':
    app.secret_key = secrets.token_hex(16)
    app.run(debug=True)
    session['username'] = None
