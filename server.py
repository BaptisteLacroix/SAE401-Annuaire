from flask import Flask, render_template, request

app = Flask(__name__, template_folder='templates')


@app.route('/')
@app.route('/index')
def index():
    # show the user profile for that user
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # show the user profile for that user
    if request.method == 'POST':
        email = request.form['E-mail']
        password = request.form['password']


@app.route('/globalSearch')
def global_search():
    # show the user profile for that user
    filter_value = request.args.get('filter')
    return render_template('globalSearch.html', filter=filter_value)


@app.route('/profile')
def profile():
    # show the user profile for that user
    return render_template('profile.html')


if __name__ == '__main__':
    app.run(debug=True)
