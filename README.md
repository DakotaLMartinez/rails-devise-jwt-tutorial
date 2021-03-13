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

In our case, we won't be needing to interact with the jwt_payload directly, so we can move on for now. Next, we'll run migrations using

```bash
rails db:migrate
```

## Add respond_with using fast_jsonapi method

As we already added the `fast_jsonapi` gem, we can generate a serializer to configure the json format we'll want to send to our front end API.

```
$ rails generate serializer user id email created_at
```

It will create a serializer with a predefined structure. Now, we have to add the attributes we want to include as a user response. So, we'll add the user's id, email and created_at. So the final version of user_serializer.rb looks like this:

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
    if resource.persisted?
      render json: {
        status: {code: 200, message: 'Logged in sucessfully.'},
        data: UserSerializer.new(resource).serializable_hash[:data][:attributes]
      }
    else
      render json: {
        status: {message: "User couldn't be created successfully. #{resource.errors.full_messages.to_sentence}"}
      }, status: :unprocessable_entity
    end
  end
end

class Users::SessionsController < Devise::SessionsController
  respond_to :json
  private

  def respond_with(resource, _opts = {})
    if resource.persisted?
      render json: {
        status: {code: 200, message: 'Logged in sucessfully.'},
        data: UserSerializer.new(resource).serializable_hash[:data][:attributes]
      }, status: :ok
    else
      render json: {
        message: "Invalid email or password. Please try again."
      }, status: :unauthorized
    end
  end

  def respond_to_on_destroy
    if current_user
      render json: {
        status: 200,
        message: "logged out successfully"
      }, status: :ok
    else
      render json: {
        status: 401,
        message: "Couldn't find an active session."
      }, status: :unauthorized
    end
  end
end
```

Remember, you can use the attribute method in a serializer to add a property to the JSON response based on an expression you return from a block that has access to the object you're serializing. For example, you can modify the column name and data format by overwrite attribute:

```rb
attribute :created_date do |user|
       user && user.created_at.strftime('%d/%m/%Y')
end
```

Here, we're adding a created_date attribute that will reformat the user's created_at value in the one we specify.

Here you can get [detailed information on fast_jsonapi](https://github.com/Netflix/fast_jsonapi).

## Finally, it’s done

Now you can add the following line in any controller to authenticate your user.

```
before_action :authenticate_user!
```

To test it, you can try this in the browser console

```js
fetch("http://localhost:3000/signup", {
  method: "post",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    user: {
      email: "test@test.com",
      password: "password",
    },
  }),
})
  .then((res) => {
    if (res.ok) {
      console.log(res.headers.get("Authorization"));
      localStorage.setItem("token", res.headers.get("Authorization"));
      return res.json();
    } else {
      throw new Error(res);
    }
  })
  .then((json) => console.dir(json))
  .catch((err) => console.error(err));
```

If everything worked correctly, we should see the token logged to the console as well as the server response looking something like this:

![Fetch Authentication Check for Devise JWT backend](https://res.cloudinary.com/dnocv6uwb/image/upload/v1607455998/fetch-auth-with-jwt-check_erkubi.jpg)

After you've got the token stored locally, you can try it out to make a request that requires authentication. To do this, we'd need to actually have a route like this that requires users to be logged in to get a response.

```
rails g controller private test
```

```rb
class PrivateController < ApplicationController
  before_action :authenticate_user!
  def test
    render json: {
      message: "This is a private message for #{current_user.email} you should only see if you've got a correct token"
    }
  end
end
```

And now, to test this out in the browser, you can run this:

```js
fetch("http://localhost:3000/private/test", {
  headers: {
    "Content-Type": "application/json",
  },
})
  .then((res) => {
    if (res.ok) {
      return res.json();
    } else if (res.status == "401") {
      throw new Error("Unauthorized Request. Must be signed in.");
    }
  })
  .then((json) => console.dir(json))
  .catch((err) => console.error(err));
```

Because we're not including the authorization token in the header, the response status should be unauthorized (401) and the error will be thrown, resulting in a rejected promise. See below:
![Result of unauthenticated request to private route](https://res.cloudinary.com/dnocv6uwb/image/upload/v1607479933/Screen_Shot_2020-12-08_at_11.42.49_AM_evbgtn.png)

As expected, without our JWT, the request is unauthorized because we have the `before_action :authenticate_user!` in our controller. So, now we can add the token in the header and see the difference

```js
fetch("http://localhost:3000/private/test", {
  headers: {
    "Content-Type": "application/json",
    Authorization: localStorage.getItem("token"),
  },
})
  .then((res) => {
    if (res.ok) {
      return res.json();
    } else if (res.status == "401") {
      throw new Error("Unauthorized Request. Must be signed in.");
    }
  })
  .then((json) => console.dir(json))
  .catch((err) => console.error(err));
```

![Authenticated fetch request in browser](https://res.cloudinary.com/dnocv6uwb/image/upload/v1607479933/Screen_Shot_2020-12-08_at_11.59.34_AM_rqremc.png)

Notice that this time we're actually able to access the private message and it includes information about the `current_user` which is now accessible on the server side because the JWT in the authorization header has correctly identified us to the server on the subsequent request.

## Handling logout

Finally, we want to be able to log a user out of our application. Our tokens only last for 30 minutes, so we'll esentially be logged out after 30 minutes of no activity. That said, we'd like to allow users to end their sessions a bit early if they so choose. To test this out. We'll want to sign in first, store the token, make a request to /private/test and make sure it works then logout and make another request to /private/test and it shouldn't work.

```js
fetch("http://localhost:3000/login", {
  method: "post",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    user: {
      email: "test@test.com",
      password: "password",
    },
  }),
})
  .then((res) => {
    if (res.ok) {
      console.log(res.headers.get("Authorization"));
      localStorage.setItem("token", res.headers.get("Authorization"));
      return res.json();
    } else {
      return res.text().then((text) => Promise.reject(text));
    }
  })
  .then((json) => console.dir(json))
  .catch((err) => console.error(err));
```

![Browser Result on successful login](https://res.cloudinary.com/dnocv6uwb/image/upload/v1607495088/fetch-auth-login-successful_lexjgm.jpg)

Notice here we see the token logged again.

Next we'll want to make the request to logout. At this point, we won't actually remove the token from localStorage, just to confirm that the same token no longer allows us to make authenticated requests. When you actually use this code, you'll want to remove the token from localStorage upon successful logout. We don't need to store a token if it's no longer valid and having a token in localStorage could be used as an indicator of an active session in conditional logic if we remove the token after a session expires.

\*\*\* Note, you'll need to make sure you include the JWT in the authorization headers of this logout request, otherwise Devise won't know which user's token to revoke.

```js
fetch("http://localhost:3000/logout", {
  method: "delete",
  headers: {
    "Content-Type": "application/json",
    Authorization: localStorage.getItem("token"),
  },
})
  .then((res) => {
    if (res.ok) {
      return res.json();
    } else {
      return res.json().then((json) => Promise.reject(json));
    }
  })
  .then((json) => {
    console.dir(json);
  })
  .catch((err) => console.error(err));
```

![Successful Async Logout request](https://res.cloudinary.com/dnocv6uwb/image/upload/v1607496671/Screen_Shot_2020-12-08_at_9.35.51_PM_f0r5mc.png)

Now if we make the the request for private/test again using the same token (still in localStorage)
using the following code:

```js
fetch("http://localhost:3000/private/test", {
  headers: {
    "Content-Type": "application/json",
    Authorization: localStorage.getItem("token"),
  },
})
  .then((res) => {
    if (res.ok) {
      return res.json();
    } else if (res.status == "401") {
      return res.text().then((text) => Promise.reject(text));
    }
  })
  .then((json) => console.dir(json))
  .catch((err) => console.error(err));
```

We'll get an error when we do so letting us know we have a revoked token.
![Request for private route using revoked token](https://res.cloudinary.com/dnocv6uwb/image/upload/v1607496716/Screen_Shot_2020-12-08_at_10.13.54_PM_ziteww.png)

We actually had to use res.text() here instead of res.json() to read this response properly.
Let's see what happens if we use the same code to request the private route, but use an expired token.

![Request to private route using expired token](https://res.cloudinary.com/dnocv6uwb/image/upload/v1607538705/Screen_Shot_2020-12-09_at_10.31.26_AM_qqh2a9.png)

Finally, let's try out the request with the header present but no token. To do this, let's remove the token from localStorage and then run the fetch again.

```js
localStorage.removeItem("token");
```

![Request Sent without any active token](https://res.cloudinary.com/dnocv6uwb/image/upload/v1607538866/Screen_Shot_2020-12-09_at_10.34.01_AM_il2xf0.png)

You can see here how your API will respond to requests made to protected routes in differing states of authorization.

| Header                                | Status | Content                                                                      |
| ------------------------------------- | ------ | ---------------------------------------------------------------------------- |
| Authorization Header with valid JWT   | 200    | successful response containing JSON                                          |
| Authorization Header with expired JWT | 401    | text response indicating `Signature has expired`                             |
| Authorization Header with no JWT      | 401    | text response indicating `You need to sign in or sign up before continuing.` |

If we want to have a separate error messages for our users if their session is expired, then we can leave things as they are. If we just wanted our users to see the `You need to sign in or signup` message, we could also store the time that a token was created in localStorage. We can introduce a function to retrieve the token and only return the token if it was created less than 30 minutes ago (or whatever your jwt expiration time is set to in the `config/initializers/devise.rb` initializer).

```js
function setToken(token) {
  localStorage.setItem("token", token);
  localStorage.setItem("lastLoginTime", new Date(Date.now()).getTime());
}
function getToken() {
  let now = new Date(Date.now()).getTime();
  let thirtyMinutes = 1000 * 60 * 30;
  let timeSinceLastLogin = now - localStorage.getItem("lastLoginTime");
  if (timeSinceLastLogin < thirtyMinutes) {
    return localStorage.getItem("token");
  }
}

fetch("http://localhost:3000/login", {
  method: "post",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    user: {
      email: "test@test.com",
      password: "password",
    },
  }),
})
  .then((res) => {
    if (res.ok) {
      setToken(res.headers.get("Authorization"));
      return res.json();
    } else {
      return res.text().then((text) => Promise.reject(text));
    }
  })
  .then((json) => console.dir(json))
  .catch((err) => console.error(err));

// Then wait 30 minutes and do this:

fetch("http://localhost:3000/private/test", {
  headers: {
    "Content-Type": "application/json",
    Authorization: getToken(),
  },
})
  .then((res) => {
    if (res.ok) {
      return res.json();
    } else if (res.status == "401") {
      return res.text().then((text) => Promise.reject(text));
    }
  })
  .then((json) => console.dir(json))
  .catch((err) => console.error(err));
```
