from flask import Flask, render_template, request
from annexe.python.login import Login

app = Flask(__name__, template_folder='templates')

LOGGING = False
LOG = None


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
    global LOGGING
    global LOG
    # Check if the user is already logged in

    if LOGGING:
        return render_template('index.html')
    if request.method == 'POST':
        # Check if the user is already logged in
        LOG = Login(request.form['username'], request.form['password'])
        is_connect = LOG.connect()
        if is_connect:
            LOGGING = True
            return render_template('index.html')
        return render_template('login.html')
    else:
        return render_template('login.html')


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """
    The function logout() is a route that renders the template index.html
    :return: The index.html file is being returned.
    """
    global LOGGING
    global LOG
    if not LOGGING:
        return render_template('index.html')
    LOG.logout()
    LOGGING = False
    return render_template('index.html')


@app.route('/globalSearch')
def global_search():
    """
    It takes a GET request with a parameter called 'filter' and renders the globalSearch.html template with the filter value
    :return: The globalSearch.html page is being returned.
    """
    # show the user profile for that user
    filter_value = request.args.get('filter')
    print(filter_value)
    return render_template('globalSearch.html', filter=filter_value)


@app.route('/profile')
def profile():
    """
    The function profile() is a route that renders the template profile.html
    :return: The profile.html file is being returned.
    """
    # show the user profile for that user
    return render_template('profile.html')


if __name__ == '__main__':
    app.run(debug=True)
