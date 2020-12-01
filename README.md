# Rails Devise JWT Tutorial

Thanks to [this tutorial on Tech Compose](https://www.techcompose.com/rails-6-api-fast_jsonapi-gem-with-devise-and-jwt-authentication/)

This article is all about authentication in rails 6 using devise and devise-jwt with fast_jsonapi response.

Fast_jsonapi
A lightning fast JSON:API serializer for Ruby Objects. It is better in performance compared to Active Model Serializer.

## Devise and JWT
Devise-jwt is a devise extension which uses JSON Web Tokens(JWT) for user authentication. With JSON Web Tokens (JWT), rather than using a cookie, a token is added to the request headers themselves (rather than stored/retrieved as a cookie). This isn’t performed automatically by the browser (as with cookies), but typically will be handled by a front-end framework as part of an AJAX call.

## Create a new Rails API app
In this step, We need to create a rails application with api_only mode with optional database params(If you want to change).

```
$ rails new rails-jwt-tutorial -–api -–database=postgresql -T
```
Here, I have created a rails 6 application using postgresql (Default SQLite).
(Note: If you are using postgresql then you have to setup database.yml)

 Configure Rack Middleware
As this is an API Only application, we have to handle ajax requests. So for that, we have to Rack Middleware for handling Cross-Origin Resource Sharing (CORS)

To do that, Just uncomment the “gem ‘rack-cors’” line from your generated Gemfile. And add the following lines to application.rb.

config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins '*'
    resource(
     '*',
     headers: :any,
     expose: ["Authorization"],
     methods: [:get, :patch, :put, :delete, :post, :options, :show]
    )
  end
end
view rawapplication.rb hosted with ❤ by GitHub
Here, we can see that there should be an “Authorization” header exposed which will be used to dispatch and receive JWT tokens in Auth headers.

 Add the needed Gems
Here, we are going to add gem like ‘devise’ and ‘devise-jwt’ for authentication and the dispatch and revocation of JWT tokens and ‘fast_jsonapi’ gem for json response.

gem 'devise'
gem 'devise-jwt'
gem 'fast_jsonapi'
view rawgemfile hosted with ❤ by GitHub
Then, do ‘bundle install’

 Configure devise
By running the following command to run a generator

$ rails generate devise:install

It is important to set our navigational formats to empty in the generated devise.rb by adding the following line since it’s an api only app.

config.navigational_formats = []
view rawdevise.rb hosted with ❤ by GitHub
Also, add the following line to config/environments/development.rb

config.action_mailer.default_url_options = { host: 'localhost', port: 3000 }
view rawdevelopment.rb hosted with ❤ by GitHub
 Create User model
You can create a devise model to represent a user. It can be named as anything. So, I’m gonna be going ahead with User. Run the following command to create User model.

$ rails generate devise User

Then run migrations using,
$ rake db:setup
or by,
$ rake db:create
$ rake db:migrate

 Create devise controllers and routes
We need to create two controllers (sessions, registrations) to handle sign ups and sign ins. By,

rails g devise:controllers users -c sessions registrations

specify that they will be responding to JSON requests. The files will looks like,

class Users::SessionsController < Devise::SessionsController
  respond_to :json
end
view rawSessionsController.rb hosted with ❤ by GitHub
class Users::RegistrationsController < Devise::SessionsController
  respond_to :json
end
view rawregistrations_controller.rb hosted with ❤ by GitHub
Then, add the routes aliases to override default routes provided by devise in the routes.rb

Rails.application.routes.draw do
  devise_for :users, path: '', path_names: {
    sign_in: 'login',
    sign_out: 'logout',
    registration: 'signup'
  },
  controllers: {
    sessions: 'users/sessions',
    registrations: 'users/registrations'
  }
end
view rawroutes.rb hosted with ❤ by GitHub
 Configure devise-jwt
Create a rake secret by running the following command.

$ bundle exec rake secret

Add the following lines to devise.rb

config.jwt do |jwt|
    jwt.secret = GENERATED_SECRET_KEY
    jwt.dispatch_requests = [
      ['POST', %r{^/login$}]
    ]
    jwt.revocation_requests = [
      ['DELETE', %r{^/logout$}]
    ]
    jwt.expiration_time = 30.minutes.to_i
end
view rawdevise.rb hosted with ❤ by GitHub
Here, we are just specifying that on every post request to login call, append JWT token to Authorization header as “Bearer” + token when there’s a successful response sent back and on a delete call to logout endpoint, the token should be revoked.

The jwt.expiration_time sets the expiration time for the generated token. In this example, it’s 30 minutes.

 Set up a revocation strategy
Revocation of token is conflicting with the main purpose of JWT token. Still devise-jwt comes with three revocation strategies out of the box. Some of them are implementations of what is discussed in the blog post JWT Revocation Strategies

Here, for the revocation of tokens, we will be using one of the 3 strategies.

Create a jwt_blacklist model by the following command

$ rails g model jwt_blacklist jti:string:index exp:datetime

Add these two lines to the “jwt_blacklist.rb”

include Devise::JWT::RevocationStrategies::Blacklist
self.table_name = 'jwt_blacklists'
view rawjwt_blacklist.rb hosted with ❤ by GitHub
Add these two options to your devise User model to specify that the model will be jwt authenticatable and will be using the blacklist model we just created for revocation.

:jwt_authenticatable, jwt_revocation_strategy: JwtBlacklist

The final user model will look like this

class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
  :recoverable, :rememberable, :validatable,
  :jwt_authenticatable, jwt_revocation_strategy: JwtBlacklist
end
view rawUser.rb hosted with ❤ by GitHub
Now run migrations using “rails db:migrate”

 Add respond_with using fast_jsonapi method
As we already added a fast_jsonapi gem. For json response for user data, we have to create a user serializer. By following command,

$ rails generate serializer user

It will create a serializer with predefined structure.Now, we have to add the attributes which we have to set as a user response. So I have added user’s id, email and created_at.So the final version of user_serializer.rb

class UserSerializer
  include FastJsonapi::ObjectSerializer
  attributes :id, :email, :created_at
end
view rawuser_serializer.rb hosted with ❤ by GitHub
We can access serializer data for single record by,

UserSerializer.new(resource).serializable_hash[:data][:attributes]
And multiple records by,
UserSerializer.new(resource).serializable_hash[:data].map{|data| data[:attributes]}

Now, we have to tell devise to communicate through JSON by adding these methods in the RegistrationsController and SessionsController

class Users::RegistrationsController < Devise::SessionsController
  respond_to :json
  private

  def respond_with(resource, _opts = {})
    render json: {
    status: {code: 200, message: 'Logged in successfully.'},
    data: UserSerializer.new(resource).serializable_hash[:data][:attributes]
    }
  end
end
view rawregistrations_controller.rb hosted with ❤ by GitHub
class Users::SessionsController < Devise::SessionsController
  respond_to :json
  private

  def respond_with(resource, _opts = {})
    render json: {
    status: {code: 200, message: 'Logged in successfully.'},
    data: UserSerializer.new(resource).serializable_hash[:data][:attributes]
    }
  end
  
  def respond_to_on_destroy
    head :ok
  end
end

  
view rawSessionsController.rb hosted with ❤ by GitHub
You can modify the column name and data format by overwrite attribute:

attribute :created_date do |user|
       user.created_at.strftime(‘%d/%m/%Y’)
end

Here, I have changed created_at attribute’s column name and its format.

Here you can get detailed information on fast_jsonapi.

 Finally, it’s done
Now you can add the following line in any controller to authenticate your user.

before_action :authenticate_user!

If you are looking to develop any project on Ruby on Rails then choose us as we are one of the leading Ruby on Rails Development Company that provides quality Ruby on Rails development services. Contact us to hire Ruby on Rails developers for your Ruby on Rails requirement or you can reach us at inquiry@techcompose.com