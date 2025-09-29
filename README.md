# Post Edit API
An API for creating and editing a blog or blog-like platform

## Authentication
For all GET requests, no authentication is needed.
For actions that affect your account (password change, deleting), you will need to send your password in the body.
For all other POST, PUT, and DELETE requests, you will need to send authentication using a JWT token that you can get at `/users/login` or `/users/{name}/reset-jwt-token`.

## Routes
See http://api.postedit.mitchk.hackclub.app/docs for more info.

Root
- GET	/

Users
- GET	/users
- GET	/users/{name}

Account Management
- POST	/users/register
- POST	/users/login
- POST	/users/{name}/reset-jwt-token
- POST	/users/{name}/set-password
- DELETE	/users/{name}/delete

Profile
- GET	/users/{name}/profile
- POST	/users/{name}/profile/create
- PUT	/users/{name}/profile/edit
- DELETE	/users/{name}/profile/delete
- GET	/users/{name}/user-comments
- POST	/users/{name}/user-comments/create
- GET	/users/{name}/user-comments/{id}
- POST	/users/{name}/user-comments/{id}/reply
- GET	/users/{name}/user-comments/{id}/replies
- PUT	/users/{name}/user-comments/{id}/edit
- DELETE	/users/{name}/user-comments/{id}/delete
- GET	/users/{name}/post-comments
- GET	/users/{name}/post-comments/{id}
- GET	/profile
- POST	/profile/create
- PUT	/profile/edit
- DELETE	/profile/delete

Comments
- GET	/users/{name}/user-comments
- POST	/users/{name}/user-comments/create
- GET	/users/{name}/user-comments/{id}
- POST	/users/{name}/user-comments/{id}/reply
- GET	/users/{name}/user-comments/{id}/replies
- PUT	/users/{name}/user-comments/{id}/edit
- DELETE	/users/{name}/user-comments/{id}/delete
- GET	/users/{name}/post-comments
- GET	/users/{name}/post-comments/{id}
- GET	/users/{name}/posts/{id}/comments
- POST	/users/{name}/posts/{id}/comments/create
- GET	/users/{name}/posts/{id}/comments/{commentId}
- POST	/users/{name}/posts/{id}/comments/{commentId}/reply
- GET	/users/{name}/posts/{id}/comments/{commentId}/replies
- PUT	/users/{name}/posts/{id}/comments/{commentId}/edit
- DELETE	/users/{name}/posts/{id}/comments/{commentId}/delete

Posts
- GET	/users/{name}/posts
- POST	/users/{name}/posts/create
- GET	/users/{name}/posts/{id}
- PUT	/users/{name}/posts/{id}/edit
- DELETE	/users/{name}/posts/{id}/delete
- GET	/users/{name}/posts/{id}/comments
- POST	/users/{name}/posts/{id}/comments/create
- GET	/users/{name}/posts/{id}/comments/{commentId}
- POST	/users/{name}/posts/{id}/comments/{commentId}/reply
- GET	/users/{name}/posts/{id}/comments/{commentId}/replies
- PUT	/users/{name}/posts/{id}/comments/{commentId}/edit
- DELETE	/users/{name}/posts/{id}/comments/{commentId}/delete
- GET	/posts
- POST	/posts/create
- GET	/posts/{id}
- PUT	/posts/{id}/edit
- DELETE	/posts/{id}/delete
