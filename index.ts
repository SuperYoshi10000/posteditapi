import * as express from "express";
import * as pg from "pg";
import * as bcrypt from "bcrypt";
import type { User, Account, Post, Comment } from "./types.d.ts";
import { generateJwt, initDatabase, dbError, checkUser, checkUserAccountAuth } from "./db.ts";

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

app.get("/users", (req, res) => {
    const users: User[] = [];
    client.query("SELECT * FROM users").then(result => {
        res.send({
            message: "List of users",
            users: result.rows
        });
    }, err => dbError(res, err));
});

app.get("/users/:name", (req, res) => {
    const { name } = req.params;
    client.query("SELECT * FROM users WHERE name = $1", [name]).then(result => {
        if (result.rows.length === 0) {
            res.status(404).send({
                error: `User with name ${name} not found`
            });
        } else {
            res.send({
                message: `User with name ${name} found`,
                user: result.rows[0]
            });
        }
    }, err => dbError(res, err));
});

// Account management

app.post("/users/register", (req, res) => {
    const { name, email, password } = req.body;
    client.query("SELECT * FROM users WHERE name = $1 OR email = $2", [name, email]).then(result => {
        if (result.rows.length > 0) {
            res.status(400).send({
                error: `User with name ${name} or email ${email} already exists`
            });
            return;
        }
        const passwordHash = bcrypt.hashSync(password, 10);
        client.query("INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
                [name, email, passwordHash]).then(result => {
            const id = result.rows[0].id;
            const token = generateJwt({ name, id });
            res.status(201).send({
                message: `User with name ${name} and email ${email} registered`,
                id,
                token
            });
        }, err => dbError(res, err));
    });
});

app.post("/users/login", (req, res) => {
    const { name, password } = req.body;
    checkUserAccountAuth(client, name, password, res, (_result, id) => {
        const token = generateJwt({ name, id });
        res.send({
            message: `User with name ${name} logged in`,
            id,
            token
        });
    });
});

app.post("/users/:name/reset-api-key", (req, res) => {
    const { name } = req.params;
    const { password } = req.body;
    checkUserAccountAuth(client, name, password, res, (_result, id) => {
        const token = generateJwt({ name, id });
        client.query("UPDATE users SET api_key = $1 WHERE name = $2", [token, name]).then(() => {
            res.send({
                message: `API key for user ${name} reset`,
                token
            });
            return;
        }, err => dbError(res, err));
    });
});
app.post("/users/:name/set-password", (req, res) => {
    const { name } = req.params;
    const { oldPassword, newPassword } = req.body;
    checkUserAccountAuth(client, name, oldPassword, res, result => {
        const newPasswordHash = bcrypt.hashSync(newPassword, 10);
        client.query("UPDATE users SET password_hash = $1 WHERE name = $2", [newPasswordHash, name]).then(() => {
            res.send({
                message: `Password for user ${name} updated`
            });
        }, err => dbError(res, err));
    });
});

app.get("/users/:name/posts", (req, res) => {
    const { name } = req.params;
    checkUser(client, name, res, result => {
        client.query("SELECT * FROM posts WHERE user = $1", [result.rows[0].id]).then(postResult => {
            res.send({
                message: `Posts for user ${name} found`,
                posts: postResult.rows
            });
        }, err => dbError(res, err));
    });
});

app.delete("/users/:name/delete", (req, res) => {
    const { name } = req.params;
    const { password } = req.body;
    checkUserAccountAuth(client, name, password, res, result => {
        client.query("DELETE FROM users WHERE name = $1", [name]).then(() => {
            res.send({
                message: `User with name ${name} deleted`
            });
        }, err => dbError(res, err));
    });
});

// User page comments

app.get("/users/:name/user-comments", (req, res) => {
    const { name } = req.params;
    checkUser(client, name, res, result => {
        client.query("SELECT * FROM user_comments WHERE user_page = $1", [result.rows[0].id]).then(commentResult => {
            res.send({
                message: `Comments for user ${name} found`,
                comments: commentResult.rows
            });
        });
    });
});
app.post("/users/:name/user-comments/create", (req, res) => {
    const { name } = req.params;
    const { content } = req.body;
    checkUser(client, name, res, result => {
        client.query("INSERT INTO user_comments (user_page, content) VALUES ($1, $2) RETURNING id", [result.rows[0].id, content]).then(commentResult => {
            res.send({
                message: `Comment added to user ${name}`,
                comment: {
                    id: commentResult.rows[0].id,
                    content: content
                }
            })
        }, err => dbError(res, err));
    });
});
app.get("/users/:name/user-comments/:id", (req, res) => {
    const { name, id } = req.params;
    res.send({
        message: `comment with user ${name} and ID ${id} found`
    });
});

app.post("/users/:name/user-comments/:id/reply", (req, res) => {
    const { name, id } = req.params;
    const { content } = req.body;
    res.send({
        message: `Reply added to comment with ID ${id} and user ${name}`,
        reply: {
            id: Date.now(),
            content: content
        }
    });
});
app.get("/users/:name/user-comments/:id/replies", (req, res) => {
    const { name, id } = req.params;
    const replies = [];
    res.send({
        message: `Replies for comment with ID ${id} and user ${name}`,
        replies: replies
    });
});

app.put("/users/:name/user-comments/:id/edit", (req, res) => {
    const { name, id } = req.params;
    const { content } = req.body;
    res.send({
        message: `Updated comment with ID ${id} and user ${name}`,
        comment: {
            id: id,
            content: content
        }
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
