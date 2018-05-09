from sqlalchemy import create_engine, asc, func
from flask import session as login_session
from database_setup import Base, Category, Item, User
from sqlalchemy.orm import sessionmaker
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from flask import Flask, render_template, request, redirect
from flask import jsonify, url_for

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog App"


# Connect to Database and create database session
engine = create_engine('sqlite:///catalogwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


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
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
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
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is \
            already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: \
        150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user \
                not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % \
        login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for \
                given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# #disconnect from any provider, still only google
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()

        del login_session['provider']
        print "You have Successfully been logged out!"
        flash("You have Successfully been logged out!")
        return redirect(url_for('showCatalog'))
    else:
        print "You were not logged in to begin with."
        flash("You were not logged in to begin with.")
        return redirect(url_for('showCatalog'))


# All categories JSON
@app.route('/catalog/JSON')
def catalogJSON():
    catalog_all = session.query(Category).all()
    items_all = session.query(Item).all()
    catalog = {"Category": [cate.serialize for cate in catalog_all]}
    for cate in catalog["Category"]:
        cate["Item"] = [item.serialize for item in items_all if
                        item.category_id == cate['id']]
    return jsonify(catalog)


# Show all categories
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    catalog = session.query(Category).order_by(asc(Category.name))
    if 'username' not in login_session:
        return render_template('publiccatalog.html', catalog=catalog)
    else:
        return render_template('catalog.html', catalog=catalog)


# show a specific Item
@app.route('/catalog/<string:cat_name>/items')
def showItems(cat_name):
    catalog = session.query(Category).order_by(asc(Category.name))
    cat = session.query(Category).filter_by(name=cat_name).one()
    items = session.query(Item).filter_by(category_id=cat.id).\
        order_by(Item.name)
    if 'username' not in login_session:
        return render_template('publicmenu.html', items=items,
                               catalog=catalog, cat=cat,
                               count=get_count(items))
    else:
        return render_template('menu.html', items=items, catalog=catalog,
                               cat=cat, count=get_count(items))


@app.route('/catalog/<string:cat_name>/<string:item_name>')
def showOneItem(cat_name, item_name):
    cat = session.query(Category).filter_by(name=cat_name).one()
    item = session.query(Item).filter_by(category_id=cat.id,
                                         name=item_name).one()
    if 'username' not in login_session:
        return render_template('publicitem.html', item=item,
                               category_id=cat.id)
    else:
        return render_template('item.html', item=item, category_id=cat.id)


# Create new Item
@app.route('/catalog/new/', methods=['GET', 'POST'])
def newItem():
    catalog = session.query(Category).order_by(asc(Category.name))
    if request.method == 'POST':
        selectedCategory = session.query(Category).\
                        filter_by(name=request.form['category']).one()
        if request.form['title']:
            print login_session['user_id']
            newItem = Item(name=request.form['title'],
                           description=request.form['description'],
                           category_id=selectedCategory.id,
                           user_id=login_session['user_id'])
            session.add(newItem)
            session.commit()
        return redirect(url_for('showItems', cat_name=selectedCategory.name))
    else:
        return render_template('newitem.html', catalog=catalog)


# Edit Item
@app.route('/catalog/<string:item_name>/<int:category_id>/edit/',
           methods=['GET', 'POST'])
def editItem(item_name, category_id):
    catalog = session.query(Category).order_by(asc(Category.name))
    itemToEdit = session.query(Item).filter_by(name=item_name,
                                               category_id=category_id).one()
    selectedCategory = session.query(Category).filter_by(id=category_id).one()
    if itemToEdit.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized \
            to edit this item. Please create your own item in order to \
            edit.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['title']:
            itemToEdit.name = request.form['title']
        if request.form['description']:
            itemToEdit.description = request.form['description']
        if request.form['category']:
            itemToEdit.category_id = category_id
        session.add(itemToEdit)
        session.commit()
        return redirect(url_for('showOneItem',
                        cat_name=selectedCategory.name,
                        item_name=itemToEdit.name))
    else:
        return render_template('edititem.html',
                               catalog=catalog, item=itemToEdit)


# Delete Item
@app.route('/catalog/<string:item_name>/<int:category_id>/delete',
           methods=['GET', 'POST'])
def deleteItem(item_name, category_id):
    itemToDelete = session.query(Item).filter_by(name=item_name,
                                                 category_id=category_id).one()
    selectedCategory = session.query(Category).\
        filter_by(id=category_id).one()
    if itemToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized \
            to delete this item. Please create your own item in order \
            to delete.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for('showItems',
                        cat_name=selectedCategory.name))
    else:
        return render_template('deleteitem.html', item=itemToDelete)


# auxiliary functions for User login control
def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def get_count(q):
    count_q = q.statement.with_only_columns([func.count()]).order_by(None)
    count = q.session.execute(count_q).scalar()
    return count

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
