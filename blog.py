import os
import re
from string import letters
import random
import hashlib
import hmac
import json
import webapp2
import jinja2
from datetime import datetime,timedelta

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir=os.path.join(os.path.dirname(__file__),'templates')
jinja_env=jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),autoescape=True)

secret="zxcvbnm";

def render_str(template,**params):
	t=jinja_env.get_template(template)
	return t.render(params)

def make_secure_val(val):
	return '%s|%s' %(val,hmac.new(secret,val).hexdigest())

def check_secure_val(secure_val):
	val=secure_val.split('|')[0]
	if secure_val==make_secure_val(val):
		return val
	

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self,d):
    	json_txt=json.dumps(d)
    	self.response.headers['Content-Type']='application/json; charset=UTF-8'
    	self.write(json_txt)
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.usr = uid and User.by_id(int(uid))
        if self.request.url.endswith('.json'):
        	self.format='json'
        else:
        	self.format='html'

    
def age_set(key,val):
	 save_time=datetime.utcnow()
   	 memcache.set(key,(val,save_time))

def age_get(key):
    r=memcache.get(key)
    if r:
    	val,save_time=r
    	age=(datetime.utcnow()-save_time).total_seconds()
    else :
    	val,age=None,0

    return val,age



def get_posts(update=False):
    	
    mc_key='BLOGS'

    posts,age=age_get(mc_key)
    if update or posts is None:
    	posts=db.GqlQuery("select * from Post order by created desc limit 10")
    	age_set(mc_key,(posts))

    return posts,age

def age_str(age):
    s='queried %s seconds ago'
    age=int(age)
    if age == 1 :
    	s=s.replace('seconds','second')
    return s % age




class MainPage(BlogHandler):
	def get(self):
    	 self.write('Welcome!!!')

def make_salt(length=5):
	return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name,pw,salt=None):
	if not salt:
		salt=make_salt()
	h=hashlib.sha256(name+pw+salt).hexdigest()
	return '%s,%s' % (salt,h)

def valid_pw(name,pw,h):
	salt=h.split(',')[0]
	return	h==make_pw_hash(name,pw,salt)	

def users_key(group='default'):
	return db.Key.from_path('users',group)

class User(db.Model):
	name=db.StringProperty(required=True)
	pw_hash=db.StringProperty(required=True)
	email=db.StringProperty()

	@classmethod
	def by_id(cls,uid):
		return User.get_by_id(uid,parent=users_key())

	@classmethod
	def by_name(cls,name):
		return User.all().filter('name=',name).get()

	@classmethod
	def register(cls,name,pw,email=None):
		pw_hash=make_pw_hash(name,pw)
		return User(parent=users_key(),
					name=name,
					pw_hash=pw_hash,
					email=email)

	@classmethod
	def login(cls,name,pw):
		u=cls.by_name(name)
		if u and valid_pw(name,pw,u.pw_hash):
			return u



class Register(BlogHandler):
	def get(self):
		self.render("signup-form.html")

	def post(self):
		error=False
		self.username=self.request.get('username')
		self.password=self.request.get('password')
		self.verify=self.request.get('verify')
		self.email=self.request.get('email')

		params=dict(username=self.username,
					email=self.email)

		if not valid_username(self.username):
			params['error_username']="That'not a valid username"
			error=True

		if not valid_password(self.password):
			params['error_password']="That's not a valid password"
			error=True

		elif self.password !=self.verify:
			params['error_verify']="Your passwords didn't match"
			error=True

		if not valid_email(self.email):
			params['error_email']="That's no a valid email"
			error=True
		if error:
			self.render('signup-form.html',**params)
		else:
			user=User.by_name(self.username)
			if user:
				msg='Tht user already exists'
				self.render('signup-form.html',error_username=msg)

			else:
				user=User.register(self.username,self.password,self.email)
				user.put()
				self.login(user)
				self.redirect('/blog')

USER_RE=re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE=re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE=re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return not email or EMAIL_RE.match(email)


class Login(BlogHandler):
	def get(self):
		self.render('login-form.html')
	def post(self):
		username=self.request.get('username')
		password=self.request.get('password')
		user=User.login(username,password)
		if user:
			self.login(user)
			self.redirect('/blog')
		else:
			msg='Invalid login'
			self.render('login-form.html',error=msg)


class Logout(BlogHandler):
	def get(self):
		self.logout()
		self.redirect('/blog')	
					


def blog_key(name='default'):
	return db.Key.from_path('blogs',name)

class Post(db.Model):
	subject=db.StringProperty(required=True)
	content=db.TextProperty(required=True)
	created=db.DateTimeProperty(auto_now_add=True)
	last_modified=db.DateTimeProperty(auto_now=True)

	def render(self):
		self._render_text=self.content.replace('\n','<br>')
		return render_str('post.html',p=self)

	def as_dict(self):
		time_format='%c'
		d={'subject':self.subject,
			'content':self.content,
			'created':self.created.strftime(time_format),
			'last_modified':self.last_modified.strftime(time_format)}
		return d

		

class BlogFront(BlogHandler):
	def get(self):
		posts,age=get_posts()
		if self.format=='html':
			self.render('front.html',posts=posts,age=age_str(age))
		else:
			return self.render_json([p.as_dict() for p in posts])

class PostPage(BlogHandler):
	def get(self,post_id):
		post_key='POST_'+post_id

		post,age=age_get(post_key)
		if not post:
			key=db.Key.from_path('Post',int(post_id),parent=blog_key())
			post=db.get(key)
			age_set(post_key,post)
			age=0

		if not post:	
			self.error(404)
			return

		if (self.format=='html'):
			self.render("permalink.html",post=post,age=age_str(age))	
		else:
			self.render_json(post.as_dict())




class NewPost(BlogHandler):
	def get(self):
		if self.usr:
			self.render("newpost.html")
		else:
			self.redirect('/login')


	def post(self):
		if not self.usr:
			self.redirect('/blog')
		subject=self.request.get('subject')
		content=self.request.get('content')

		if subject and content:
			p=Post(parent=blog_key(),subject=subject,content=content)
			p.put()
			get_posts(update=True)
			self.redirect('/blog/%s' % str(p.key().id()))

		else:
			error="please enter subject and content "
			self.render("newpost.html",subject=subject,content=content,error=error)


app=webapp2.WSGIApplication([('/',MainPage),
							('/blog/?(?:.json)?',BlogFront),
							('/blog/newpost',NewPost),
							('/blog/([0-9]+)(?:.json)?',PostPage),
							('/signup',Register),
							('/login',Login),
							('/logout',Logout),
							],
							debug=True)