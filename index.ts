import * as express from "express";
import * as pg from "pg";
import * as bcrypt from "bcrypt";
import fs from "fs";
import type { User, Account, Post, Comment } from "./types.d.ts";
import { generateJwt, initDatabase, dbError, checkUserExists, checkUserAccountAuth, PUBLIC_KEY, query, checkCorrectUser, checkAuthentication, checkUserAuthentication } from "./util.ts";
import { profile } from "console";

const app = express();
const port = 3000;

const db = new pg.Pool({
    user: "postgres",
    host: "localhost",
    database: "postedit",
    password: "password",
    port: 5432
});
let client: pg.PoolClient;


app.get("/", (req, res) => {
    res.send({
        message: "API Root"
    });
});

app.get("/public-key", (req, res) => {
    res.send({
        message: "Public key retrieved",
        publicKey: PUBLIC_KEY
    });
});

app.get("/users", (req, res) => {
    const users: User[] = [];
    query(client, res, "SELECT * FROM users", ({rows: users}) => {
        res.send({
            message: "List of users",
            users
        });
    });
});

app.get("/users/:name", (req, res) => {
    const { name } = req.params;
    checkUserExists(client, name, res, ({rows: [user]}) => {
        if (!user) {
            res.status(404).send({
                error: `User with name ${name} not found`
            });
        } else {
            res.send({
                message: `User with name ${name} found`,
                user
            });
        }
    });
});

// Account management

app.post("/users/register", (req, res) => {
    const { name, email, password } = req.body;
    query(client, res, "SELECT * FROM users WHERE name = $1 OR email = $2", [name, email], ({rowCount}) => {
        if (rowCount) { // 0 or null means no user found, and this can never be negative
            res.status(400).send({
                error: `User with name ${name} or email ${email} already exists`
            });
            return;
        }
        const passwordHash = bcrypt.hashSync(password, 10);
        query(client, res, "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING *", [name, email, passwordHash], ({rows: [user]}) => {
            const {id} = user;
            const token = generateJwt({ name, id });
            res.status(201).send({
                message: `User with name ${name} and email ${email} registered`,
                id,
                token,
                publicKey: PUBLIC_KEY
            });
        });
    });
});

app.post("/users/login", (req, res) => {
    const { name, password } = req.body;
    checkUserAccountAuth(client, name, password, res, (_, id) => {
        const token = generateJwt({ name, id });
        res.send({
            message: `User with name ${name} logged in`,
            id,
            token,
            publicKey: PUBLIC_KEY
        });
    });
});

// app.post("/users/:name/reset-api-key", (req, res) => {
//     const { name } = req.params;
//     const { password } = req.body;
//     checkUserAccountAuth(client, name, password, res, (_result, id) => {
//         const token = generateJwt({ name, id });
//         query(client, res, "UPDATE users SET api_key = $1 WHERE name = $2", [token, name]).then(() => {
//             res.send({
//                 message: `API key for user ${name} reset`,
//                 token
//             });
//             return;
//         }, err => dbError(res, err));
//     });
// });
app.post("/users/:name/set-password", (req, res) => {
    const { name } = req.params;
    const { oldPassword, newPassword } = req.body;
    checkUserAccountAuth(client, name, oldPassword, res, () => {
        const newPasswordHash = bcrypt.hashSync(newPassword, 10);
        query(client, res, "UPDATE users SET password_hash = $1 WHERE name = $2", [newPasswordHash, name], () => {
            res.send({
                message: `Password for user ${name} updated`
            });
        });
    });
});

app.delete("/users/:name/delete", (req, res) => {
    const { name } = req.params;
    const { password } = req.body;
    checkUserAccountAuth(client, name, password, res, () => {
        query(client, res, "DELETE FROM users WHERE name = $1", [name], () => {
            res.send({
                message: `User with name ${name} deleted`
            });
        });
    });
});

app.get("/users/:name/posts", (req, res) => {
    const { name } = req.params;
    checkUserExists(client, name, res, ({rows: [user]}) => {
        query(client, res, "SELECT * FROM posts WHERE user = $1", [user.id], ({rows: posts}) => {
            res.send({
                message: `Posts for user ${name} found`,
                posts
            });
        });
    });
});


// Profile management

app.post("/users/:name/profile/create", (req, res) => {
    const { name } = req.params;
    const { displayName, bio, about, profilePictureUrl } = req.body;
    checkUserExists(client, name, res, ({rows: [user]}) => {
        // check api key here
        const currentUserId = user.id; // Assuming the current user is the one creating the profile (temporarily using user.id as currentUserId, adjust as needed)
        if (!checkCorrectUser(res, user.id, currentUserId, "create a profile for yourself")) return;
        
        query(client, res, "INSERT INTO profiles (user, display_name, bio, about, profile_picture_url) VALUES ($1, $2, $3, $4, $5) RETURNING *", [user.id, displayName, bio, about, profilePictureUrl], ({rows: [profile]}) => {
            res.send({
                message: `Profile for user ${name} created`,
                profile
            });
        });
    });
});
app.get("/users/:name/profile", (req, res) => {
    const { name } = req.params;
    checkUserExists(client, name, res, ({rows: [user]}) => {
        query(client, res, "SELECT * FROM profiles WHERE user = $1", [user.id], ({rows: [profile]}) => {
            if (!profile) {
                res.status(404).send({
                    error: `No profile found for user ${name}`
                });
                return;
            }
            res.send({
                message: `Profile for user ${name} found`,
                profile
            });
        });
    });
});
app.put("/users/:name/profile/edit", (req, res) => {
    const { name } = req.params;
    const { displayName, bio, about, profilePictureUrl } = req.body;
    checkUserExists(client, name, res, (_, userId) => {
        let queryFields: string[] = [];
        if ("displayName" in req.body) queryFields.push("display_name = $1");
        if ("bio" in req.body) queryFields.push("bio = $2");
        if ("about" in req.body) queryFields.push("about = $3");
        if ("profilePictureUrl" in req.body) queryFields.push("profile_picture_url = $4");
        if (queryFields.length === 0) {
            res.status(400).send({
                error: "No fields to update"
            });
            return;
        }
        
        // check api key here
        const currentUserId = userId; // Assuming the current user is the one updating the profile (temporarily using userId as currentUserId, adjust as needed)
        if (!checkCorrectUser(res, userId, currentUserId, "update your own profile")) return;

        query(client, res, `UPDATE profiles SET ${queryFields.join(", ")} WHERE user = $5 RETURNING *`, [displayName, bio, about, profilePictureUrl, userId], ({rows: [profile]}) => {
            if (!profile) {
                res.status(404).send({
                    error: `No profile found for user ${name}`
                });
                return;
            }
            res.send({
                message: `Profile for user ${name} updated`,
                profile
            });
        });
    });
});
app.delete("/users/:name/profile/delete", (req, res) => {
    const { name } = req.params;
    checkUserAuthentication(client, name, req, res, "delete your own profile", true, (_, userId) => {
        query(client, res, "DELETE FROM profiles WHERE user = $1", [userId], () => {
            res.send({
                message: `Profile for user ${name} deleted`
            });
        });
    });
});

// User page comments

app.get("/users/:name/user-comments", (req, res) => {
    const { name } = req.params;
    checkUserExists(client, name, res, (_, userId) => {
        query(client, res, "SELECT * FROM user_comments WHERE user_page = $1", [userId], ({rows: comments}) => {
            res.send({
                message: `Comments for user ${name} found`,
                comments
            });
        });
    });
});
app.post("/users/:name/user-comments/create", (req, res) => {
    const { name } = req.params;
    const { content } = req.body;
    checkUserAuthentication(client, name, req, res, "comment while logged in", false, (_, userId, currentUserId) => {
        query(client, res, "INSERT INTO user_comments (user_page, user, content) VALUES ($1, $2, $3) RETURNING *", [userId, currentUserId, content], ({rows: [comment]}) => {
            res.send({
                message: `Comment added to user ${name}`,
                comment
            });
        });
    });
});
app.get("/users/:name/user-comments/:id", (req, res) => {
    const { name, id } = req.params;
    checkUserExists(client, name, res, (_, userId) => {
        query(client, res, "SELECT * FROM user_comments WHERE user_page = $1 AND id = $2", [userId, id], ({rows: [comment]}) => {
            if (!comment) {
                res.status(404).send({
                    error: `No comment found with ID ${id} for user ${name}`
                });
                return;
            }
            res.send({
                message: `Comment with ID ${id} for user ${name} found`,
                comment
            });
        });
    });
});

app.post("/users/:name/user-comments/:id/reply", (req, res) => {
    const { name, id } = req.params;
    const { content } = req.body;
    checkUserAuthentication(client, name, req, res, "reply to a comment while logged in", false, (_, userId, currentUserId) => {
        query(client, res, "INSERT INTO user_comments (user_page, user, parent, content) VALUES ($1, $2, $3, $4) RETURNING *", [userId, currentUserId, id, content], ({rows: [reply]}) => {
            res.send({
                message: `Reply added to comment with ID ${id} for user ${name}`,
                reply
            });
        });
    });
});
app.get("/users/:name/user-comments/:id/replies", (req, res) => {
    const { name, id } = req.params;
    checkUserExists(client, name, res, (_, userId) => {
        query(client, res, "SELECT * FROM user_comments WHERE user_page = $1 AND parent = $2", [userId, id], ({rows: replies}) => {
            res.send({
                message: `Replies for comment with ID ${id} for user ${name}`,
                replies
            });
        });
    });
});

app.put("/users/:name/user-comments/:id/edit", (req, res) => {
    const { name, id } = req.params;
    const { content } = req.body;
    checkUserAuthentication(client, name, req, res, (_, userId) => {
        
        query(client, res, "UPDATE user_comments SET content = $1 WHERE user_page = $2 AND id = $3 RETURNING *", [content, userId, id], ({rows: [comment]}) => {
            if (!comment) {
                res.status(404).send({
                    error: `No comment found with ID ${id} for user ${name}`
                });
                return;
            }
            res.send({
                message: `Comment with ID ${id} for user ${name} updated`,
                comment
            });
        });
    });
});
app.delete("/users/:name/user-comments/:id/delete", (req, res) => {
    const { name, id } = req.params;
    res.send({
        message: `Deleted comment with ID ${id} and user ${name}`
    });
});

// User post comments
    
app.get("/users/:name/post-comments", (req, res) => {
    const { name } = req.params;
    res.send({
        message: `comments with user ${name} found`
    });
});
app.get("/users/:name/post-comments/:id", (req, res) => {
    const { name, id } = req.params;
    res.send({
        message: `comment with user ${name} and post ID ${id} found`
    });
});

// Profile management for your own profile
app.get("/profile", (req, res) => {
    // Assuming the user is authenticated and we have their ID
    const userId = 1; // Replace with actual user ID from authentication context
    query(client, res, "SELECT * FROM profiles WHERE user = $1", [userId], ({rows: [profile]}) => {
        if (!profile) {
            res.status(404).send({
                error: `No profile found for user ${userId}`
            });
            return;
        }
        res.send({
            message: `Profile for user ${userId} found`,
            profile
        });
    });
});
app.post("/profile/create", (req, res) => {
    // Assuming the user is authenticated and we have their ID
    const userId = 1;
    const { displayName, bio, about, profilePictureUrl } = req.body;
    query(client, res, "INSERT INTO profiles (user, display_name, bio, about, profile_picture_url) VALUES ($1, $2, $3, $4, $5) RETURNING *", [userId, displayName, bio, about, profilePictureUrl], ({rows: [profile]}) => {
        res.send({
            message: `Profile for user ${userId} created`,
            profile
        });
    });
});
app.put("/profile/edit", (req, res) => {
    // Assuming the user is authenticated and we have their ID
    const userId = 1;
    const { displayName, bio, about, profilePictureUrl } = req.body;
    let queryFields: string[] = [];
    if ("displayName" in req.body) queryFields.push("display_name = $1");
    if ("bio" in req.body) queryFields.push("bio = $2");
    if ("about" in req.body) queryFields.push("about = $3");
    if ("profilePictureUrl" in req.body) queryFields.push("profile_picture_url = $4");
    if (queryFields.length === 0) {
        res.status(400).send({
            error: "No fields to update"
        });
        return;
    }
    query(client, res, `UPDATE profiles SET ${queryFields.join(", ")} WHERE user = $5 RETURNING *`, [displayName, bio, about, profilePictureUrl, userId], ({rows: [profile]}) => {
        if (!profile) {
            res.status(404).send({
                error: `No profile found for user ${userId}`
            });
            return;
        }

        res.send({
            message: `Profile for user ${userId} updated`,
            profile
        });
    });
});
app.delete("/profile/delete", (req, res) => {
    // Assuming the user is authenticated and we have their ID
    const userId = 1;
    query(client, res, "DELETE FROM profiles WHERE user = $1", [userId], () => {
        res.send({
            message: `Profile for user ${userId} deleted`
        });
    });
});

// Posts, for the current user

app.get("/posts", (req, res) => {
    const posts = {};
    res.send({
        message: "List of posts",
        posts: posts
    });
});
app.get("/posts/:id", (req, res) => {
    const { id } = req.params;
    res.send({
        message: `post with ID ${id} found`
    });
});
app.post("/posts/create", (req, res) => {
    const { postName, content } = req.body;
    res.send({
        message: `Created post with name ${postName}`,
    });
});
app.put("/posts/:id/edit", (req, res) => {
    const { id } = req.params;
    const { postName, content } = req.body;
    res.send({
        message: `Updated post with ID ${id} and name ${postName}`,
    });
});
app.delete("/posts/:id/delete", (req, res) => {
    const { id } = req.params;
    res.send({
        message: `Deleted post with ID ${id}`
    });
});

// Posts

app.post("/users/:name/posts/create", (req, res) => {
    const { name } = req.params;
    const { postName, content } = req.body;
    res.send({
        message: `Created post with user ${name}`
    });
});

app.get("/users/:name/posts/:id", (req, res) => {
    const { name, id } = req.params;
    res.send({
        message: `post user is ${name} and ID is ${id}`
    });
});

app.put("/users/:name/posts/:id/edit", (req, res) => {
    const { name, id } = req.params;
    res.send({
        message: `Updated post with ID ${id} and user ${name}`
    });
});

app.delete("/users/:name/posts/:id/delete", (req, res) => {
    const { name, id } = req.params;
    res.send({
        message: `Deleted post with ID ${id} and user ${name}`
    });
});

// Post comments

app.get("/users/:name/posts/:id/comments", (req, res) => {
    const { name, id } = req.params;
    const comments = [];
    res.send({
        message: `Comments for post with ID ${id} and user ${name}`,
        comments: comments
    });
});

// Post a comment to a post
app.post("/users/:name/posts/:id/comments/create", (req, res) => {
    const { name, id } = req.params;
    const { content } = req.body;
    res.send({
        message: `Comment added to post with ID ${id} and user ${name}`,
        comment: {
            id: Date.now(),
            content: content
        }
    });
});

// Get a comment by its ID (also applies to replies)
app.get("/users/:name/posts/:id/comments/:commentId", (req, res) => {
    const { name, id, commentId } = req.params;
    res.send({
        message: `Comment with ID ${commentId} for post with ID ${id} and user ${name} found`
    });
});
// Get all replies to a comment
app.post("/users/:name/posts/:id/comments/:commentId/reply", (req, res) => {
    const { name, id, commentId } = req.params;
    const { content } = req.body;
    res.send({
        message: `Reply added to comment with ID ${commentId} for post with ID ${id} and user ${name}`,
        reply: {
            id: Date.now(),
            content: content
        }
    });
});

app.get("/users/:name/posts/:id/comments/:commentId/replies", (req, res) => {
    const { name, id, commentId } = req.params;
    const replies = [];
    res.send({
        message: `Replies for comment with ID ${commentId} for post with ID ${id} and user ${name}`,
        replies: replies
    });
});

app.put("/users/:name/posts/:id/comment/:commentId/edit", (req, res) => {
    const { name, id, commentId } = req.params;
    const { content } = req.body;
    res.send({
        message: `Updated comment with ID ${commentId} for post with ID ${id} and user ${name}`,
        comment: {
            id: commentId,
            content: content
        }
    });
});

app.delete("/users/:name/posts/:id/comments/:commentId/delete", (req, res) => {
    const { name, id, commentId } = req.params;
    res.send({
        message: `Deleted comment with ID ${commentId} for post with ID ${id} and user ${name}`
    });
});




app.listen(port, async () => {
    console.log(`Server is running at http://localhost:${port}`);
    client = await db.connect().catch(err => {
        console.error("Database connection error:", err);
        process.exit(1);
    });
    await initDatabase(client);
});
