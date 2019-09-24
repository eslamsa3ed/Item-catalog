from flask import (
   Flask,
   render_template,
   request,
   redirect,
   jsonify,
   url_for,
   flash,
   make_response,
   session as login_session,
   abort
)
from sqlalchemy import create_engine, asc, exc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import httplib2
import json
import random
import requests
import string

app = Flask(__name__)

# load env file which contain our secrets \(0_0)/
env = json.loads(open('env.json', 'r').read())
# google secrets
secrets = json.loads(open('client_secret.json', 'r').read())

# Connect to the database and create a database session.
engine = create_engine('sqlite:///item_catalog.db',
                       connect_args={'check_same_thread': False})

# Bind the above engine to a session.
Session = sessionmaker(bind=engine)

# Create a Session object.
session = Session()


@app.route('/')
def home():
    """Homepage function"""

    categories = session.query(Category).all()
    items = session.query(Item).order_by(Item.id.desc()).all()
    return render_template('home.html', categories=categories, items=items)

# CATEGORIS FUNCTION ##


# view Category
@app.route('/catalog/<cat_name>/items')
def view_category(cat_name):
    """View all items in category """

    category = session.query(Category).filter_by(name=cat_name).first()
    # check if category exist
    if category is None:
        abort(404)
    else:
        categories = session.query(Category).all()
        items = session.query(Item).filter_by(category_id=category.id)

    return render_template(
        'category.html', categories=categories, category=category, items=items)


# Add a new category.
@app.route("/catalog/category/new/", methods=['GET', 'POST'])
def add_category():
    """Add new category function"""

    if 'username' not in login_session:
        flash("Unauthorized, Please log in to access.", 'danger')
        return redirect(url_for('login'))
    elif request.method == 'POST':
        if request.form['catename'] == '':
            flash('Name fields is required.', 'danger')
            return redirect(url_for('add_category'))

        category = session.query(Category).\
            filter_by(name=request.form['catename']).first()
        if category is not None:
            flash('Category with same name already exists.', 'danger')
            return redirect(url_for('add_category'))

        new_category = Category(
            name=request.form['catename'],
            user_id=login_session['user_id'])
        session.add(new_category)
        session.commit()
        flash(
            'New category %s successfully created!' %
            new_category.name, 'success')
        return redirect(url_for('home'))
    else:
        categories = session.query(Category).all()
        return render_template('newCategory.html', categories=categories)

# Delete Category


@app.route('/catalog/<cat_name>/delete', methods=['GET', 'POST'])
def delete_category(cat_name):
    """Delete category function """

    category = session.query(Category).filter_by(name=cat_name).first()

    # check if category exists
    if category is None:
        abort(404)
    elif 'username' not in login_session:
        flash("Unauthorized, Please log in to access.", 'danger')
        return redirect(url_for('login'))
    elif category.user_id is not login_session['user_id']:
        flash("Unauthorized, You didn't have permission\
               to delete this category", 'danger')
        return redirect(url_for('home'))
    elif request.method == 'POST':
        session.query(Item).filter_by(category=category).delete()
        session.delete(category)
        session.commit()
        flash('Category %s successfully Deleted!' % category.name, 'success')
        return redirect('/')

    return render_template('confirmDelete.html', item=category)

# Edit Category


@app.route('/catalog/<cat_name>/edit', methods=['GET', 'POST'])
def edit_category(cat_name):
    """Edit category function """

    category = session.query(Category).filter_by(name=cat_name).first()

    # check if category exists
    if category is None:
        abort(404)
    elif 'username' not in login_session:
        flash("Unauthorized, Please log in to access.", 'danger')
        return redirect(url_for('login'))
    elif category.user_id is not login_session['user_id']:
        flash("Unauthorized, You didn't have permission\
               to edit this category", 'danger')
        return redirect(url_for('home'))
    elif request.method == 'POST':
        category.name = request.form['catename']
        session.add(category)
        session.commit()
        flash('Category %s successfully Edited!' % category.name, 'success')
        return redirect(url_for('view_category', cat_name=category.name))
    else:
        allCategories = session.query(Category).filter_by(name=cat_name).all()

    return render_template('editCategory.html',
                           category=category, allCategories=allCategories)

# ITEMS FUNCTIONS ##


# Add a new item in category.
@app.route("/catalog/<cate_name>/item/new", methods=['GET', 'POST'])
def add_item(cate_name):
    """Add new item to category function"""
    category = session.query(Category).\
        filter_by(name=cate_name).first()
    if category is None:
        flash('Error Category not found.', 'danger')
        return redirect(url_for('home'))

    if 'username' not in login_session:
        flash("Unauthorized, Please log in to access.", 'danger')
        return redirect(url_for('login'))
    elif request.method == 'POST':
        if request.form['itemName'] == '':
            flash('Name fields is required.', 'danger')
            return redirect(url_for('add_item', cate_name=cate_name))

        item = session.query(Item).\
            filter_by(name=request.form['itemName'], category=category).first()

        if item is not None:
            flash(
                'Item with same name already exists in category %s.' %
                cate_name, 'danger')
            return redirect(url_for('add_item', cate_name=cate_name))

        else:
            new_item = Item(
                name=request.form['itemName'],
                category_id=category.id,
                description=request.form['itemDescription'],
                user_id=login_session['user_id'])
            session.add(new_item)
            session.commit()
        flash('New item %s successfully created!' % new_item.name, 'success')
        return redirect(url_for('home'))
    else:
        items = session.query(Item).filter_by(category_id=category.id)
        return render_template(
            'newItem.html', category=category, allItems=items)


# view Item
@app.route('/catalog/<cat_name>/<item_name>')
def view_item(cat_name, item_name):
    """ view Item """

    category = session.query(Category).filter_by(name=cat_name).first()
    item = session.query(Item).filter_by(
        name=item_name, category=category).first()
    # check if category exist
    if category is None or item is None:
        abort(404)
    else:
        items = session.query(Item).filter_by(category=category)

    return render_template('item.html', category=category,
                           item=item, allItems=items)


# Edit Item
@app.route('/catalog/<cat_name>/<item_name>/edit', methods=['GET', 'POST'])
def edit_item(cat_name, item_name):
    """Edit Item in Category function """

    category = session.query(Category).filter_by(name=cat_name).first()
    item = session.query(Item).filter_by(
        name=item_name, category=category).first()
    # check if category  and item exists
    if category is None or item is None:
        abort(404)
    elif 'username' not in login_session:
        flash("Unauthorized, Please log in to access.", 'danger')
        return redirect(url_for('login'))
    elif item.user_id is not login_session['user_id']:
        flash("Unauthorized, You didn't have permission\
               to edit this item", 'danger')
        return redirect(url_for('home'))
    elif request.method == 'POST':
        item.name = request.form['itemName']
        item.description = request.form['itemDescription']
        item.category_id = request.form['itemCateId']
        session.add(item)
        session.commit()
        flash('Item %s successfully edited!' % item.name, 'success')
        return redirect(
            url_for('view_item', cat_name=item.category.name,
                    item_name=item.name))
    else:
        items = session.query(Item).filter_by(category_id=category.id)
        categories = session.query(Category).all()
    return render_template('editItem.html', allCategories=categories,
                           category=category, item=item, allItems=items)


# Delete Item
@app.route('/catalog/<cat_name>/<item_name>/delete', methods=['GET', 'POST'])
def delete_item(cat_name, item_name):
    """Delete item function """

    category = session.query(Category).filter_by(name=cat_name).first()
    item = session.query(Item).filter_by(
        name=item_name, category=category).first()
    # check if category  and item exists
    if category is None or item is None:
        abort(404)
    elif 'username' not in login_session:
        flash("Unauthorized, Please log in to access.", 'danger')
        return redirect(url_for('login'))
    elif item.user_id is not login_session['user_id']:
        flash("Unauthorized, You didn't have permission\
               to delete this item", 'danger')
        return redirect(url_for('home'))
    elif request.method == 'POST':
        session.delete(item)
        session.commit()
        flash('Item %s successfully Deleted!' % item.name, 'success')
        return redirect(url_for('view_category', cat_name=cat_name))

    return render_template('confirmDelete.html', item=item)

# USERS FUNCTIONS


# login function
@app.route('/login')
def login():

    # Create anti-forgery state token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    GclientId = secrets["web"]["client_id"]
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state, clientId=GclientId)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    google_id = credentials.id_token['sub']
    if result['user_id'] != google_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != secrets["web"]["client_id"]:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_google_id = login_session.get('google_id')
    if stored_access_token is not None and google_id == stored_google_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['google_id'] = google_id

    # Get user info.
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    # Assing Email as name if User does not have Google+
    if "name" in data:
        login_session['username'] = data['name']
    else:
        name_corp = data['email'][:data['email'].find("@")]
        login_session['username'] = name_corp
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if the user exists. If it doesn't, make a new one.
    try:
        user = session.query(User).filter_by(email=data["email"]).one()
    except BaseException:
        user = None

    if user is None:
        user = create_user(login_session)

    login_session['user_id'] = user.id

    return "Ok"


# Disconnect Google Account.
def gdisconnect():
    """Disconnect the Google account of the current logged-in user."""

    # Only disconnect the connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Log out the currently connected user.
@app.route('/logout')
def logout():
    """Log out the currently connected user."""

    if 'username' in login_session:
        gdisconnect()
        del login_session['google_id']
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash("You have been successfully logged out!", 'success')
        return redirect(url_for('home'))
    else:
        flash("You were not logged in!", 'danger')
        return redirect(url_for('home'))


# Create new user.
def create_user(login_session):
    """Crate a new user.
    Argument:
    login_session (dict): The login session.
    """

    new_user = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture']
    )
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user


# profile
@app.route('/profile')
def profile():
    if 'username' not in login_session:
        flash("Unauthorized,login to access", 'danger')
        return redirect(url_for('login'))
    return render_template('profile.html')

# JSON ENDPOINTS FUNCTIONS


# Return JSON of all the categories in the catalog.
@app.route('/categories.json')
def categories_json():
    """Returns JSON of all the categories in the catalog."""

    categories = session.query(Category).all()
    categories = [i.serialize for i in categories]
    return jsonify(categories)


# Return JSON of all the items in the catalog.
@app.route('/items.json')
def item_json():
    """Returns JSON of all the items in the catalog."""

    items = session.query(Item).all()
    items = [r.serialize for r in items]
    return jsonify(items)


if __name__ == "__main__":
    app.secret_key = env["appSecreteKey"]
    app.run(host="127.0.0.1", port=5000, debug=True)
