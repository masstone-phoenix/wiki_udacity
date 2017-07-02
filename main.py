#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import webapp2
import re
import jinja2
import os
from google.appengine.ext import ndb
from google.appengine.api import memcache
import random
import string
import hashlib
import hmac
import json
import datetime
import time
import logging


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


DEBUG = True
PAGE_RE = r'/((?:\w+/?)*)'


# cookie
cookie_secret = 'clyz'
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(cookie_secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#user password bcryptic
def make_salt(length = 5):
    return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)



# jinja render
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# memcache
def age_set(key, val):
    save_time = datetime.utcnow()
    memcache.add(key, (val, save_time))

def age_get(key):
    r = memcache.get(key)
    if r:
        val, save_time = r
        age = (datetime.utcnow() - save_time).total_seconds()
    else:
        val, age = None, 0

    return val, age

#######################################################################
# wiki model
def wiki_key(name = 'default'):
    return ndb.Key('wiki', name)

class WikiItem(ndb.Model):
    url_addr = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("blog_item.html", p = self)
    
    def as_dict(self):
        time_fmt = '%c'
        d = {
                'url_addr': self.subject,
                'content': self.content,
                'created': self.created.strftime(time_fmt)
            }
        return d

    @classmethod
    def by_addr(cls, addr):
        w =  WikiItem.query(WikiItem.url_addr == addr).order(-WikiItem.last_modified).get()
        return w
    
    @classmethod
    def history_by_addr(cls, addr):
        return  WikiItem.query(ancestor == wiki_key(addr)).query(WikiItem.url_addr == addr).order(-WikiItem.last_modified)

    @classmethod
    def add(cls, addr, content):
        if addr:
            k = wiki_key(addr)
        else:
            k = wiki_key()
        w = WikiItem(parent = k,
                    url_addr = addr,
                    content = content)
        w.put()
        return w


#mainpage some foundation function
class WikiBase(Handler):
    def render_str(self, template, **params):
        params['user'] = self.user
        params['addr'] = self.request.path[1:]
        t = jinja_env.get_template(template)
        return t.render(params)
    
    def render_json(self, d, cls=None):
        json_txt = json.dumps(d, cls=cls)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
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
        logging.debug(repr(self)+'login')
        self.set_secure_cookie('user_id', str(user.key.id()))
    
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'referer=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(long(uid))
        
        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'


class WikiPage(WikiBase):
    def get(self, addr):
        # get addr from wiki db
        aWiki = WikiItem.by_addr(addr)
        logging.debug('WikiPage: ' + addr + ' wiki: ' + repr(aWiki))
        # query once more
        if not aWiki:
            time.sleep(0.5)
            aWiki = WikiItem.by_addr(addr)
            logging.debug('Once more WikiPage: ' + addr + ' wiki: ' + repr(aWiki))
        
        if aWiki:
            self.render('wiki_item.html', content = aWiki.content);
        else:
            self.redirect('/_edit/{0}'.format(addr))



class EditPage(WikiBase):
    def render_newpost(self, content='', error=''):
        self.render('newpost.html', content=content, error=error)
    
    def get(self, addr):
        if self.user:
            aWiki = WikiItem.by_addr(addr)
            content = ''
            if aWiki:
                content = aWiki.content
            self.render_newpost(content = content)
        else:
            self.redirect('/login')

    def post(self, addr):
        logging.debug('edit post url: '+repr(self.request.url) + 'addr: ' + addr)
        if not self.user:
            self.redirect('/login')
        
        content = self.request.get("content")
        
        if content:
            item = WikiItem.add(addr, content)
            
            # cache
#            blogItems = BlogItem.query()
#            memcache.add(blogItems_key, blogItems)
#            memcache.add(blogItems_date,  datetime.datetime.now())
#            memcache.add(str(item.key.id()), item)
#            memcache.add(str(item.key.id())+'date', datetime.datetime.now())

            self.redirect('/{0}'.format(addr))
        else:
            error = 'content, please!'
            self.render_newpost(content=content, error=error)


#class BlogItemHandler(Handler):
#    def get(self, id):
#        item = memcache.get(id)
#        itemDate = memcache.get(id+'date')
#        if not item:
#            item = BlogItem.get_by_id(long(id))
#        
#        if not itemDate:
#            age = '0'
#        else:
#            age = '{0}'.format((datetime.datetime.now() - itemDate).total_seconds())
#        self.render('blog_item.html', subject=item.subject, content=item.content, age=age)
#self.response.write(item)



#user sign up
def users_key(group = 'default'):
    return ndb.Key('users', group)

class User(ndb.Model):
    name = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty()
    
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())
    
    @classmethod
    def by_name(cls, name):
        u = User.query().filter(User.name == name).get()
        return u
    
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)
    
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)



# for subclass
class Signup(WikiBase):
    def get(self):
        logging.debug(repr(self)+'signup get')
        if self.request.referer:
            self.set_secure_cookie('referer', str(self.request.referer))
        self.render('blog_signup.html')
    
    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        
        
        params = dict(username = self.username,
                      email = self.email)
            
        if not valid_username(self.username):
            params['username_error'] = "That's not a valid username."
            have_error = True
                      
        if not valid_password(self.password):
            params['password_error'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['verify_error'] = "Your passwords didn't match."
            have_error = True
                                                  
        if not valid_email(self.email):
            params['email_error'] = "That's not a valid email."
            have_error = True
                                                              
        if have_error:
            self.render('blog_signup.html', **params)
        else:
            self.done(str(self.read_secure_cookie('referer')))
                                                                      
    def done(self, *a, **kw):
        raise NotImplementedError



class Register(Signup):
    def done(self, url):
        logging.debug(repr(self)+'done')
        #make sure the user doesn't already exist
        u = ndb.gql("SELECT * FROM User WHERE name  = :user", user=self.username).get()
        if u:
            logging.info(repr(self)+'u')
            msg = 'That user already exists.'
            self.render('blog_signup.html', username_error = msg)
        else:
            logging.info(repr(self)+'not u')
            u = User.register(self.username, self.password, self.email)
            u.put()
            
            self.login(u)
            self.redirect(url)


class LoginHandler(WikiBase):
    def get(self):
        if self.request.referer:
            logging.debug('login get : '+ self.request.referer.encode('ascii', errors='ignore'))
            self.set_secure_cookie('referer', str(self.request.referer))
        self.render('blog_login.html')

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        u = User.login(username, password)
        if u:
            self.login(u)
            logging.debug('login post : '+ repr(self.read_secure_cookie('referer')))
            self.redirect(str(self.read_secure_cookie('referer')))
        else:
            msg = 'Invalid login'
            self.render('blog_login.html', error = msg)


class LogoutHandler(WikiBase):
    def get(self):
        self.logout()
        self.redirect(self.request.referer)



# to JSON
class CJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, datetime.date):
            return obj.strftime('%Y-%m-%d')
        else:
            return json.JSONEncoder.default(self, obj)

class JsonHandler(webapp2.RequestHandler):
    def get(self, id = None):
        if id:
            item = BlogItem.get_by_id(long(id))
            self.response.headers['Content-Type'] = 'application/json'
            self.response.write(json.dumps(item.to_dict(exclude=['key']), cls=CJsonEncoder))
        else:
            blogItems = BlogItem.query()
            self.response.headers['Content-Type'] = 'application/json'
            self.response.write(json.dumps([item.to_dict(exclude=['key']) for item in blogItems], cls=CJsonEncoder))

class FlushHandler(webapp2.RequestHandler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')


#logging.debug('This is a debug message')
#logging.info('This is an info message')
#logging.warning('This is a warning message')
#logging.error('This is an error message')
#logging.critical('This is a critical message')
app = webapp2.WSGIApplication([
                               ('/signup', Register),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage),
                               ], debug=DEBUG)
