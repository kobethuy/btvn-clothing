import jinja2, os, sys, webapp2, csv
from webapp2_extras import auth
from webapp2_extras import sessions

from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

config = {
  'webapp2_extras.auth': {
    'user_model': 'models.User',
    'user_attributes': ['name']
  },
  'webapp2_extras.sessions': {
  'secret_key': 'DontYouDareChangeThis'
  }
}

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

class BaseHandler(webapp2.RequestHandler):
	@webapp2.cached_property
	def auth(self):
		"""Shortcut to access the auth instance as a property."""
		return auth.get_auth()
	
	@webapp2.cached_property
	def user_info(self):
		"""Shortcut to access a subset of the user attributes that are stored
		in the session.
	
		The list of attributes to store in the session is specified in
		config['webapp2_extras.auth']['user_attributes'].
		:returns
		A dictionary with most user information
		"""
		return self.auth.get_user_by_session()
	
	@webapp2.cached_property
	def user(self):
		"""Shortcut to access the current logged in user.
	
		Unlike user_info, it fetches information from the persistence layer and
		returns an instance of the underlying model.
	
		:returns
		The instance of the user model associated to the logged in user.
		"""
		u = self.user_info
		return self.user_model.get_by_id(u['user_id']) if u else None
	
	@webapp2.cached_property
	def user_model(self):
		"""Returns the implementation of the user model.
	
		It is consistent with config['webapp2_extras.auth']['user_model'], if set.
		"""
		return self.auth.store.user_model
	
	@webapp2.cached_property
	def session(self):
		"""Shortcut to access the current session."""
		return self.session_store.get_session(backend="datastore")

	# this is needed for webapp2 sessions to work
	def dispatch(self):
		# Get a session store for this request.
		self.session_store = sessions.get_store(request=self.request)
	
		try:
			# Dispatch the request.
			webapp2.RequestHandler.dispatch(self)
		finally:
			# Save all sessions.
			self.session_store.save_sessions(self.response)

class Index(webapp2.RequestHandler):

	def get(self):

		f = open("productsdatabase.csv")
		content = csv.reader(f)
		ghibli = []
		titan = []

		title = "Home"

		for bar in content:
			if "Ghibli" in bar[1]:
				ghibli.append(bar)
			else:
				titan.append(bar)
		f.close()
		template_values = {
			'Title': title,
			'ghibli': ghibli,
			'titan': titan,
		}

		template = JINJA_ENVIRONMENT.get_template('templates/products.html')
		self.response.write(template.render(template_values))
		
class Login(BaseHandler):
	def get(self, errormsg=""):
		title = "Login"
		
		template_values = {
			'Title': title,
			'Error': errormsg,
		}
		
		template = JINJA_ENVIRONMENT.get_template('templates/login.html')
		self.response.write(template.render(template_values))

	def post(self):

		username = self.request.get('username')
		password = self.request.get('password')
		remember = self.request.get('remember')

		if (username == "" or password ==""):
			self.get("Please enter your Email & Password")
			return

		try:
			u = self.auth.get_user_by_password(username, password, remember=remember)
			self.redirect('/')
		except (InvalidAuthIdError, InvalidPasswordError) as e:
			self.get("Unable to login! Incorrect Email or Password!")

class Register(BaseHandler):
	def get(self, errormsg = ""):
		title = "Register"

		template_values = {
			'Title': title,
			'Error': errormsg,
		}
		template = JINJA_ENVIRONMENT.get_template('templates/register.html')
		self.response.write(template.render(template_values))

	def post(self):
		first_name = self.request.get('username')
		last_name = self.request.get('lastname')
		email = self.request.get('email')
		password = self.request.get('password')
		password_check = self.request.get('passwordcheck')

		if password != password_check:
			self.get("Unable to create your account\nPasswords not matched!")
			return
		
		unique_properties = ['email_address']

		user_data = self.user_model.create_user(email,
		email_address=email, name=first_name, password_raw=password,
		last_name=last_name)
		
		if not user_data[0]: #user_data is a tuple
			self.get("Unable to create your account!\nEmail has already been used!")
			return

		user = user_data[1]
		user_id = user.get_id()

		token = self.user_model.create_signup_token(user_id)
		self.redirect('/')
		
class Policy(webapp2.RequestHandler):
	def get(self):
		title = "Policy"

		template_values = {
			'Title': title,
		}
		template = JINJA_ENVIRONMENT.get_template('templates/policy.html')
		self.response.write(template.render(template_values))

class Details(webapp2.RequestHandler):

	def get(self):

		f = open("productsdatabase.csv")

		content = csv.reader(f)

		name = ""
		price = ""
		url = ""
		title = "Details"

		product = self.request.get('p')

		for a in content:
			print "Query:"
			print a
			if product == a[0]:
				name = a[2]
				price = a[4]
				url = a[3]
		f.close()

		template_values = {
			'Title': title,
			'Product_name': name,
			'Price': price,
			'Img_link': url,
		}
		template = JINJA_ENVIRONMENT.get_template('templates/details.html')
		self.response.write(template.render(template_values))

class Search(webapp2.RequestHandler):
	def get(self):

		title = "Search"

		query = self.request.get('q').replace(" ", "+")

		template_values = {
			'Title': title,
		}

		template = JINJA_ENVIRONMENT.get_template('templates/search.html')
		self.response.write(template.render(template_values))

class Cart(webapp2.RequestHandler):
	def get(self):

		title = "Shopping Cart"

		template_values = {
			'Title': title,
		}

		template = JINJA_ENVIRONMENT.get_template('templates/cart.html')
		self.response.write(template.render(template_values))

class About(webapp2.RequestHandler):
	def get(self):

		title = "About"

		template_values = {
			'Title': title,
		}

		template = JINJA_ENVIRONMENT.get_template('templates/about.html')
		self.response.write(template.render(template_values))

app = webapp2.WSGIApplication([
    ('/', Index),
	('/details', Details),
	('/about', About),
	('/cart', Cart),
	('/search', Search),
	('/login', Login),
	('/register', Register),
	('/policy', Policy)], debug=True, config=config)