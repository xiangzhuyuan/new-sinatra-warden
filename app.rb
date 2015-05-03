require 'bundler'
Bundler.require

# load the Database and User model
require './model'

# 这里是调用 Warden::Strategies.add 接口来添加验证逻辑;
Warden::Strategies.add(:password) do
  def valid?
    params['user'] && params['user']['username'] && params['user']['password']
  end

  def authenticate!
    user = User.first(username: params['user']['username'])

    if user.nil?
      throw(:warden, message: "The username you entered does not exist.")
    elsif user.authenticate(params['user']['password'])
      success!(user)
    else
      throw(:warden, message: "The username and password combination ")
    end
  end
end

class SinatraWardenExample < Sinatra::Base
  enable :sessions, :logging
  register Sinatra::Flash
  set :session_secret, "supersecret"
  use Warden::Manager do |config|
    # 这里需要告诉 Warden 怎么来序列化用户信息到会话里.
    config.serialize_into_session { |user| user.id }
    # 怎么反序列化用户信息
    config.serialize_from_session { |id| User.get(id) }

    config.scope_defaults :default,
                          # "strategies" is an array of named methods with which to
                          # attempt authentication. We have to define this later.
                          # 策略也就是一个方法名的数组, 用来验证.
                          strategies: [:password],
                          # The action is a route to send the user to when
                          # warden.authenticate! returns a false answer. We'll show
                          # this route below.

                          # 这个 action 在这里的作用是告诉 warden.auth 在失败后路由到哪里.
                          action:     'auth/unauthenticated'
    # When a user tries to log in and cannot, this specifies the
    # app to send the user to.
    config.failure_app = self
  end

  Warden::Manager.before_failure do |env, opts|
    env['REQUEST_METHOD'] = 'POST'
  end

  get '/' do
    erb :index
  end

  get '/auth/login' do
    erb :login
  end

  post '/auth/login' do
    env['warden'].authenticate!

    flash[:success] = env['warden'].message

    if session[:return_to].nil?
      redirect '/'
    else
      redirect session[:return_to]
    end
  end

  get '/auth/logout' do
    env['warden'].raw_session.inspect
    env['warden'].logout
    flash[:success] = 'Successfully logged out'
    redirect '/'
  end

  post '/auth/unauthenticated' do
    session[:return_to] = env['warden.options'][:attempted_path] if session[:return_to].nil?

    # Set the error and use a fallback if the message is not defined
    flash[:error]       = env['warden.options'][:message] || "You must log in"
    redirect '/auth/login'
  end

  get '/protected' do
    env['warden'].authenticate!

    erb :protected
  end
end
