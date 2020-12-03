# Rails Devise JWT Tutorial

Thanks to [this tutorial on Tech Compose](https://www.techcompose.com/rails-6-api-fast_jsonapi-gem-with-devise-and-jwt-authentication/) and the [devise](https://github.com/heartcombo/devise) and [devise-jwt](https://github.com/waiting-for-dev/devise-jwt) gems. Also this [blog post on token recovation strategies](http://waiting-for-dev.github.io/blog/2017/01/24/jwt_revocation_strategies/) was helpful to me.

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

## Configure Rack Middleware
As this is an API Only application, we have to handle ajax requests. So for that, we have to Rack Middleware for handling Cross-Origin Resource Sharing (CORS)

To do that, Just uncomment the 
```
gem 'rack-cors'
``` 
line from your generated Gemfile. And uncomment the contents of `config/initialzers/cors.rb` the following lines to application.rb, adding an expose option in the process:

```rb
# config/initializers/cors.rb
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
```

Here, we can see that there should be an "Authorization" header exposed which will be used to dispatch and receive JWT tokens in Auth headers.

## Add the needed Gems

Here, we are going to add gem like ‘devise’ and ‘devise-jwt’ for authentication and the dispatch and revocation of JWT tokens and ‘fast_jsonapi’ gem for json response.
```rb
gem 'devise'
gem 'devise-jwt'
gem 'fast_jsonapi'
```

Then, do 
```bash
bundle install
```

## Configure devise
By running the following command to run a generator
```
$ rails generate devise:install
```
It is important to set our navigational formats to empty in the generated devise.rb by uncommenting and modifying the following line since it’s an api only app.
```
config.navigational_formats = []
```

Also, add the following line to config/environments/development.rb
```
config.action_mailer.default_url_options = { host: 'localhost', port: 3000 }
```

## Create User model
You can create a devise model to represent a user. It can be named as anything. So, I’m gonna be going ahead with User. Run the following command to create User model.
```
$ rails generate devise User
```
Then run migrations using,

```
$ rails db:create
$ rails db:migrate
```
## Create devise controllers and routes
We need to create two controllers (sessions, registrations) to handle sign ups and sign ins. 
```
rails g devise:controllers users -c sessions registrations
```
specify that they will be responding to JSON requests. The files will look like this:
```rb
class Users::SessionsController < Devise::SessionsController
  respond_to :json
end
```
```rb
class Users::RegistrationsController < Devise::RegistrationsController
  respond_to :json
end
```
Then, add the routes aliases to override default routes provided by devise in the routes.rb

```rb
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
```

## Configure devise-jwt

Add the following lines to devise.rb
```rb
config.jwt do |jwt|
    jwt.secret = Rails.application.credentials.fetch(:secret_key_base)
    jwt.dispatch_requests = [
      ['POST', %r{^/login$}]
    ]
    jwt.revocation_requests = [
      ['DELETE', %r{^/logout$}]
    ]
    jwt.expiration_time = 30.minutes.to_i
end
```

Here, we are just specifying that on every post request to login call, append JWT token to Authorization header as “Bearer” + token when there’s a successful response sent back and on a delete call to logout endpoint, the token should be revoked.

The `jwt.expiration_time` sets the expiration time for the generated token. In this example, it’s 30 minutes.

## Set up a revocation strategy
Revocation of tokens is an important security concern. The `devise-jwt` gme comes with three revocation strategies out of the box. You can read more about them in this [blog post on token recovation strategies](http://waiting-for-dev.github.io/blog/2017/01/24/jwt_revocation_strategies/). 

For now, we'll be going with the one they recommended with is to store a single valid user attached token with the user record in the users table.

Here, the model class acts itself as the revocation strategy. It needs a new string column with name `jti` to be added to the user. `jti` stands for JWT ID, and it is a standard claim meant to uniquely identify a token.

It works like the following:

- When a token is dispatched for a user, the `jti` claim is taken from the `jti` column in the model (which has been initialized when the record has been created).
- At every authenticated action, the incoming token `jti` claim is matched against the `jti` column for that user. The authentication only succeeds if they are the same.
- When the user requests to sign out its `jti` column changes, so that provided token won't be valid anymore.

In order to use it, you need to add the `jti` column to the user model. So, you have to set something like the following in a migration:

```ruby
def change
  add_column :users, :jti, :string, null: false
  add_index :users, :jti, unique: true
  # If you already have user records, you will need to initialize its `jti` column before setting it to not nullable. Your migration will look this way:
  # add_column :users, :jti, :string
  # User.all.each { |user| user.update_column(:jti, SecureRandom.uuid) }
  # change_column_null :users, :jti, false
  # add_index :users, :jti, unique: true
end
```

To add this, we can run
```
rails g migration addJtiToUsers jti:string:index:unique
```
And then make sure to add `null: false` to the `add_column` line and `unique: true` to the `add_index` line

**Important:** You are encouraged to set a unique index in the `jti` column. This way we can be sure at the database level that there aren't two valid tokens with same `jti` at the same time.

Then, you have to add the strategy to the model class and configure it accordingly:

```ruby
class User < ApplicationRecord
  include Devise::JWT::RevocationStrategies::JTIMatcher

  devise :database_authenticatable,
         :jwt_authenticatable, jwt_revocation_strategy: self
end
```

Be aware that this strategy makes uses of `jwt_payload` method in the user model, so if you need to use it don't forget to call `super`:

```ruby
def jwt_payload
  super.merge('foo' => 'bar')
end
```

Now run migrations using 
```bash
rails db:migrate
```

## Add respond_with using fast_jsonapi method
As we already added a fast_jsonapi gem. For json response for user data, we have to create a user serializer. By following command,

```
$ rails generate serializer user id email created_at
```
It will create a serializer with predefined structure.Now, we have to add the attributes which we have to set as a user response. So I have added user’s id, email and created_at. So the final version of user_serializer.rb looks like this:
```rb
class UserSerializer
  include FastJsonapi::ObjectSerializer
  attributes :id, :email, :created_at
end
```

We can access serializer data for single record by,
```rb
UserSerializer.new(resource).serializable_hash[:data][:attributes]
And multiple records by,
UserSerializer.new(resource).serializable_hash[:data].map{|data| data[:attributes]}
```

Now, we have to tell devise to communicate through JSON by adding these methods in the `RegistrationsController` and `SessionsController`

```rb
class Users::RegistrationsController < Devise::RegistrationsController
  respond_to :json
  private

  def respond_with(resource, _opts = {})
    render json: {
    status: {code: 200, message: 'Logged in successfully.'},
    data: UserSerializer.new(resource).serializable_hash[:data][:attributes]
    }
  end
end

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
```
  
You can modify the column name and data format by overwrite attribute:
```rb
attribute :created_date do |user|
       user && user.created_at.strftime('%d/%m/%Y')
end
```
Here, I have changed created_at attribute’s column name and its format.

Here you can get detailed information on fast_jsonapi.

## Finally, it’s done
Now you can add the following line in any controller to authenticate your user.
```
before_action :authenticate_user!
```
To test it, you can try this in the browser console

```js
fetch('http://localhost:3000/signup', {  
    method: 'post',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ "user": {
      "email" : "test@test.com",
      "password" : "password"
    }})
})
  .then(res => {
    console.log(res.headers.get('Authorization'))
    return res.json()
  })
  .then(json => console.dir(json))
```
I've been working with this quite a bit, and while I can see the Bearer token in the authorization headers of the Response. I'm not able to access them within the `res` variable. I just get an empty headers object instead. The idea would be to access that header and store the token either in a cookie or localStorage, but I'm not currently able to access the token in the header programatically. 

Any ideas?

To replicate, you'd probably need to run:

```
git clone git@github.com:DakotaLMartinez/rails-devise-jwt-tutorial.git
cd rails-devise-jwt-tutorial
rails db:create
rails db:migrate
rails s
```

Then in a browser console somewhere:
```
fetch('http://localhost:3000/signup', {  
    method: 'post',
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Expose-Headers': 'Authorization',
      'Access-Control-Allow-Headers': 'Authorization',
      'credentials': 'include'
    },
    body: JSON.stringify({ "user": {
      "email" : "test@test.com",
      "password" : "password"
    }})
})
  .then(res => {
    debugger
    return res.json()
  })
  .then(json => console.dir(json))
```

If you have another terminal open running the `rails console` you can see that the user is in fact created. And then in the network tab in the browser dev tools the authorization header is there in the response, but it's not accessible within the fetch response. I've read about this being a server side issue in that the server is not granting access to the header via javascript, but it looks to me like I've done that properly. I'm really stumped here and would be grateful for any help y'all might be able to provide :)