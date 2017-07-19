import os
import re 
from string import letters
import webapp2
import jinja2
import hashlib
import hmac
import random
from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = "secret"

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

#cookie hashing
def make_secure_val(val):
	return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split("|")[0]
	if secure_val == make_secure_val(val):
		return val

class Handler(webapp2.RequestHandler):
	"""Webapp and Jinja template"""
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw)) 

	def set_secure_cookie(self, name, val):
		cookie_val= make_secure_val(val)
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def inittialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

#user stuff
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

def make_salt(length=5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return ndb.Key.from_path('users', group)

class User(ndb.Model):
	username= ndb.StringProperty(required=True)
	pw_hash= ndb.StringProperty(required=True)
	email= ndb.StringProperty()


class Blog(ndb.Model):
	#database 
	subject= ndb.StringProperty(required=True)
	content= ndb.TextProperty(required=True)
	created= ndb.DateTimeProperty(auto_now_add=True)
	last_modified= ndb.DateTimeProperty(auto_now= True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str('post.html', p= self)

class MainPage(Handler): 
	#blog entries page, blogs are rendered from the database with the following functions
	def get(self, subject="", content=""):
		blogs= ndb.gql("SELECT * FROM Blog ORDER BY created DESC")
		self.render("blogist.html", blogs=blogs)

class SignUpHandler(Handler):
	#signup form and cookies
	def get(self):
		self.render("signup.html")
		
	def post(self):
		have_error= False
		username= self.request.get('username')
		password= self.request.get('password')
		verify= self.request.get('verify')
		email= self.request.get('email')

		params = dict(username = username, email = email)

		if not valid_username(username):
			params['error_username'] = "That's not a valid username."
			have_error = True
		if not valid_password(password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif password != verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True
		if not valid_email(email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup.html', **params)
		else:
			pw_hash = make_pw_hash(username, password)
			user= User(username= username, pw_hash=pw_hash, email=email)
			user.put()
			self.redirect('/welcome?username=' + username)

class Welcome(Handler):
	def get(self):
		username= self.request.get('username')
		if valid_username(username):
			self.render('welcome.html', username= username)
		else:
			self.redirect('signup.html')


class BlogPage(Handler):
	"""The individual page for every blog post"""
	def get(self, post_id):
		key= ndb.Key(Blog, int(post_id))
		blog = key.get()

		if not blog:
			self.error(404)
			return

		self.render('permalink.html', blog= blog)
		
		
class BlogHandler(Handler):
	# new posts page, render fields and take parameters for blogs, check if entry is complete
	def get(self):
		self.render("newpost.html")

	def post(self):
		subject= self.request.get('subject')
		content= self.request.get('content')

		if subject and content:
			p = Blog(subject= subject, content= content)
			key= p.put()
			self.redirect('/%s' % str(key.id()))
		else:
			error="Please provide both a subject and a blog entry!"
			self.render("newpost.html", subject=subject, content= content, error=error)


app = webapp2.WSGIApplication([('/', MainPage),
							   ('/newpost', BlogHandler),
							   ('/signup', SignUpHandler),
							   ('/welcome', Welcome),
							   ('/([0-9]+)', BlogPage)], debug=True)