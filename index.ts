import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import "dotenv/config";
import { generateJwt, initDatabase, checkUserExists, checkUserAccountAuth, query, checkCorrectUser, checkUserAuth, queryResultOrElse, getUserFromAuth, requireValue } from "./util.ts";
import { absolutePath } from "swagger-ui-dist";

const app = express();
const port = Number(process.env.PORT) || 3000;

const db = new pg.Pool({
    user: process.env.DB_USER || "postgres",
    host: process.env.DB_HOST || "localhost",
    database: process.env.DB_NAME || "postedit",
    password: process.env.DB_PASSWORD || undefined,
    port: Number(process.env.DB_PORT || 5432),
    ssl: process.env.DB_SSL === "false" ? false : Boolean(process.env.DB_SSL) || false,
});
let client: pg.PoolClient;


app.get("/", (req, res) => {
    res.send({
        message: "Post Edit API Root"
    });
});

// app.get("/public-key", (req, res) => {
//     res.send({
//         message: "Public key retrieved",
//         publicKey: PUBLIC_KEY
//     });
// });

app.get("/users", async (req, res) => {
    const {rows: users} = await query(client, res, "SELECT * FROM users");
    res.send({
        message: "List of users",
        users
    });
});

app.get("/users/:name", async (req, res) => {
    const { name } = req.params;
    const {rows: [user]} = await queryResultOrElse(client, res, "SELECT * FROM users WHERE name = $1", [name], `No user found with name ${name}`);
    res.send({
        message: `User with name ${name} found`,
        user
    }); 
});

// Account management

app.post("/auth/register", async (req, res) => {
    const { name, email, password } = req.body;
    requireValue(name, res, "Name is required");
    requireValue(email, res, "Email is required");
    requireValue(password, res, "Password is required");
    const {rowCount} = await query(client, res, "SELECT * FROM users WHERE name = $1 OR email = $2", [name, email]);
    if (rowCount) { // 0 or null means no user found, and this can never be negative
        res.status(400).send({
            error: `User with name ${name} or email ${email} already exists`
        });
        return;
    }
    const passwordHash = bcrypt.hashSync(password, 10);
    const {rows: [user]} = await query(client, res, "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING *", [name, email, passwordHash]);
    const {id} = user;
    const token = generateJwt({ name, id });
    res.status(201).send({
        message: `User with name ${name} and email ${email} registered`,
        id,
        token,
        // publicKey: PUBLIC_KEY
    });
});
app.post("/auth/login", async (req, res) => {
    const { name, password } = req.body;
    requireValue(name, res, "Name is required");
    requireValue(password, res, "Password is required");
    const [,userId] = await checkUserAccountAuth(client, name, password, res);
    const token = generateJwt({ name, id: userId });
    res.send({
        message: `User with name ${name} logged in`,
        id: userId,
        token,
        // publicKey: PUBLIC_KEY
    });
});
app.post("/auth/reset-jwt-token", async (req, res) => {
    const { name, password } = req.body;
    let userId: string;
    if (req.headers.authorization) [,userId] = await getUserFromAuth(client, req, res);
    else [,userId] = await checkUserAccountAuth(client, name, password, res);
    
    const token = generateJwt({ name, id: userId });
    res.send({
        message: `JWT token for user ${name} reset`,
        id: userId,
        token,
        // publicKey: PUBLIC_KEY
    });
});
app.post("/auth/set-password", async (req, res) => {
    const { name, oldPassword, newPassword } = req.body;
    await checkUserAccountAuth(client, name, oldPassword, res);
    const newPasswordHash = bcrypt.hashSync(newPassword, 10);
    await queryResultOrElse(client, res, "UPDATE users SET password_hash = $1 WHERE name = $2", [newPasswordHash, name], `No user found with name ${name}`);
    res.send({
        message: `Password for user ${name} updated`
    });
});
app.delete("/auth/delete", async (req, res) => {
    const { name, password } = req.body;
    const [,userId] = await checkUserAccountAuth(client, name, password, res);
    await query(client, res, "DELETE FROM users WHERE name = $1", [name]);
    res.send({
        message: `User with name ${name} deleted`
    });
});
app.post("/users/:name/auth/reset-jwt-token", async (req, res) => {
    const { name } = req.params;
    const { password } = req.body;
    let userId: string;
    if (req.headers.authorization) [,userId] = await getUserFromAuth(client, req, res);
    else [,userId] = await checkUserAccountAuth(client, name, password, res);
    
    const token = generateJwt({ name, id: userId });
    res.send({
        message: `JWT token for user ${name} reset`,
        id: userId,
        token,
        // publicKey: PUBLIC_KEY
    });
});
app.post("/users/:name/auth/set-password", async (req, res) => {
    const { name } = req.params;
    const { oldPassword, newPassword } = req.body;
    await checkUserAccountAuth(client, name, oldPassword, res);
    const newPasswordHash = bcrypt.hashSync(newPassword, 10);
    await queryResultOrElse(client, res, "UPDATE users SET password_hash = $1 WHERE name = $2", [newPasswordHash, name], `No user found with name ${name}`);
    res.send({
        message: `Password for user ${name} updated`
    });
});
app.delete("/users/:name/auth/delete", async (req, res) => {
    const { name } = req.params;
    const { password } = req.body;
    const [,userId] = await checkUserAccountAuth(client, name, password, res);
    await query(client, res, "DELETE FROM users WHERE name = $1", [name]);
    res.send({
        message: `User with name ${name} deleted`
    });
});


app.get("/users/:name/posts", async (req, res) => {
    const { name } = req.params;
    const [,userId] = await checkUserExists(client, name, res);
    const {rows: posts} = await query(client, res, "SELECT * FROM posts WHERE author = $1", [userId]);
    res.send({
        message: `Posts for user ${name} found`,
        posts
    });
});


// Profile management

app.post("/users/:name/profile/create", async (req, res) => {
    const { name } = req.params;
    const { displayName, bio, about, profilePictureUrl } = req.body;
    const [,userId] = await checkUserExists(client, name, res);
    // check api key here
    const currentUserId = userId; // Assuming the current user is the one creating the profile (temporarily using user.id as currentUserId, adjust as needed)
    if (!checkCorrectUser(res, userId, currentUserId, "create a profile for yourself")) return;
    
    let {rows: [profile]} = await query(client, res, "INSERT INTO profiles (owner, display_name, bio, about, profile_picture_url) VALUES ($1, $2, $3, $4, $5) RETURNING *", [userId, displayName, bio, about, profilePictureUrl]);
    res.send({
        message: `Profile for user ${name} created`,
        profile
    });
});
app.get("/users/:name/profile", async (req, res) => {
    const { name } = req.params;
    const [,userId] = await checkUserExists(client, name, res);
    const {rows: [profile]} = await queryResultOrElse(client, res, "SELECT * FROM profiles WHERE owner = $1", [userId], `No profile found for user ${name}`);
    res.send({
        message: `Profile for user ${name} found`,
        profile
    });
});
app.put("/users/:name/profile/edit", async (req, res) => {
    const { name } = req.params;
    const { displayName, bio, about, profilePictureUrl } = req.body;
    const [,userId, currentUserId] = await checkUserAuth(client, name, req, res, "update your own profile", false);
    if (!checkCorrectUser(res, userId, currentUserId, "update your own profile")) return;
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
    const {rows: [profile]} = await queryResultOrElse(client, res, `UPDATE profiles SET ${queryFields.join(", ")} WHERE owner = $5 RETURNING *`, [displayName, bio, about, profilePictureUrl, userId], `No profile found for user ${name}`);
    res.send({
        message: `Profile for user ${name} updated`,
        profile
    });
});
app.delete("/users/:name/profile/delete", async (req, res) => {
    const { name } = req.params;
    const [,userId] = await checkUserAuth(client, name, req, res, "delete your own profile", true);
    await query(client, res, "DELETE FROM profiles WHERE owner = $1", [userId]);
    res.send({
        message: `Profile for user ${name} deleted`
    });
});

// User page comments

app.get("/users/:name/user-comments", async (req, res) => {
    const { name } = req.params;
    const [,userId] = await checkUserExists(client, name, res);
    const {rows: comments} = await query(client, res, "SELECT * FROM user_comments WHERE user_page = $1", [userId]);
    res.send({
        message: `Comments for user ${name} found`,
        comments
    });
});
app.post("/users/:name/user-comments/create", async (req, res) => {
    const { name } = req.params;
    const { content } = req.body;
    const [,userId, currentUserId] = await checkUserAuth(client, name, req, res);
    const {rows: [comment]} = await query(client, res, "INSERT INTO user_comments (user_page, author, content) VALUES ($1, $2, $3) RETURNING *", [userId, currentUserId, content]);
    res.send({
        message: `Comment added to user ${name}`,
        comment
    });
});
app.get("/users/:name/user-comments/:id", async (req, res) => {
    const { name, id } = req.params;
    const [,userId] = await checkUserExists(client, name, res);
    const {rows: [comment]} = await queryResultOrElse(client, res, "SELECT * FROM user_comments WHERE user_page = $1 AND id = $2", [userId, id], `No comment found with ID ${id} for user ${name}`);
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
app.post("/users/:name/user-comments/:id/reply", async (req, res) => {
    const { name, id } = req.params;
    const { content } = req.body;
    const [,userId, currentUserId] = await checkUserAuth(client, name, req, res, "reply to a comment while logged in");
    const {rows: [reply]} = await query(client, res, "INSERT INTO user_comments (user_page, author, parent, content) VALUES ($1, $2, $3, $4) RETURNING *", [userId, currentUserId, id, content]);
    res.send({
        message: `Reply added to comment with ID ${id} for user ${name}`,
        reply
    });
});
app.get("/users/:name/user-comments/:id/replies", async (req, res) => {
    const { name, id } = req.params;
    const [,userId] = await checkUserExists(client, name, res);
    const {rows: replies} = await query(client, res, "SELECT * FROM user_comments WHERE user_page = $1 AND parent = $2", [userId, id]);
    res.send({
        message: `Replies for comment with ID ${id} for user ${name}`,
        replies
    });
});


app.put("/users/:name/user-comments/:id/edit", async (req, res) => {
    const { name, id } = req.params;
    const { content } = req.body;
    const [,userId, currentUserId] = await checkUserAuth(client, name, req, res);
    // await queryResultOrElse(client, res, "SELECT * FROM user_comments WHERE user_page = $1 AND id = $2", [userId, id], "No comment found to edit");
    const {rows: [comment]} = await queryResultOrElse(client, res, "UPDATE user_comments SET content = $1 WHERE user_page = $2 AND id = $3 AND author = $4 RETURNING *", [content, userId, id, currentUserId], [403, "You can only edit your own comment"]);
    res.send({
        message: `Comment with ID ${id} for user ${name} updated`,
        comment
    });
});
app.delete("/users/:name/user-comments/:id/delete", async (req, res) => {
    const { name, id } = req.params;
    const [,userId, currentUserId] = await checkUserAuth(client, name, req, res);
    // await queryResultOrElse(client, res, "SELECT * FROM user_comments WHERE user_page = $1 AND id = $2", [userId, id], "No comment found to delete");
    await queryResultOrElse(client, res, "DELETE FROM user_comments WHERE user_page = $1 AND id = $2 AND author = $3", [userId, id, currentUserId], [403, "You can only delete your own comment"]);
    res.send({
        message: `Comment with ID ${id} for user ${name} deleted`
    });
});

// User post comments
    
app.get("/users/:name/post-comments", async (req, res) => {
    const { name } = req.params;
    const [,userId] = await checkUserExists(client, name, res);
    const {rows: comments} = await query(client, res, "SELECT * FROM post_comments WHERE author = $1", [userId]);
    res.send({
        message: `Comments for user ${name} found`,
        comments
    });
});
app.get("/users/:name/post-comments/:id", async (req, res) => {
    const { name, id } = req.params;
    const [,userId] = await checkUserExists(client, name, res);
    const {rows: [comment]} = await queryResultOrElse(client, res, "SELECT * FROM post_comments WHERE author = $1 AND id = $2", [userId, id], `No comment found with ID ${id} for user ${name}`);
    res.send({
        message: `Comment with ID ${id} for user ${name} found`,
        comment
    });
});

// Profile management for your own profile
app.get("/profile", async (req, res) => {
    const [,userId] = await getUserFromAuth(client, req, res);
    const {rows: [profile]} = await queryResultOrElse(client, res, "SELECT * FROM profiles WHERE owner = $1", [userId], `No profile found for user ${userId}`);
    res.send({
        message: `Profile for user ${userId} found`,
        profile
    });
});
app.post("/profile/create", async (req, res) => {
    const [,userId] = await getUserFromAuth(client, req, res);
    const { displayName, bio, about, profilePictureUrl } = req.body;
    requireValue(displayName, res, "Display name is required");
    const {rows: [profile]} = await query(client, res, "INSERT INTO profiles (owner, display_name, bio, about, profile_picture_url) VALUES ($1, $2, $3, $4, $5) RETURNING *", [userId, displayName, bio, about, profilePictureUrl]);
    res.send({
        message: `Profile for user ${userId} created`,
        profile
    });
});
app.put("/profile/edit", async (req, res) => {
    const { displayName, bio, about, profilePictureUrl } = req.body;
    const [,userId] = await getUserFromAuth(client, req, res);
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
    const {rows: [profile]} = await queryResultOrElse(client, res, `UPDATE profiles SET ${queryFields.join(", ")} WHERE owner = $5 RETURNING *`, [displayName, bio, about, profilePictureUrl, userId], `No profile found for user ${userId}`);
    res.send({
        message: `Profile for user ${userId} updated`,
        profile
    });
});
app.delete("/profile/delete", async (req, res) => {
    const [,userId] = await getUserFromAuth(client, req, res);
    await queryResultOrElse(client, res, "DELETE FROM profiles WHERE owner = $1", [userId], `No profile found for user ${userId}`);
    res.send({
        message: `Profile for user ${userId} deleted`
    });
});

// Posts, for the current user

app.get("/posts", async (req, res) => {
    const [,userId] = await getUserFromAuth(client, req, res);
    const {rows: posts} = await query(client, res, "SELECT * FROM posts WHERE author = $1", [userId]);
    res.send({
        message: "List of posts",
        posts
    });
});
app.get("/posts/:id", async (req, res) => {
    const { id } = req.params;
    const [,userId] = await getUserFromAuth(client, req, res);
    const {rows: [post]} = await queryResultOrElse(client, res, "SELECT * FROM posts WHERE author = $1 AND id = $2", [userId, id], `No post found with ID ${id}`);
    res.send({
        message: `post with ID ${id} found`,
        post
    });
});
app.post("/posts/create", async (req, res) => {
    const { postName, content } = req.body;
    const [,userId] = await getUserFromAuth(client, req, res);
    requireValue(postName, res, "Post name is required");
    requireValue(content, res, "Content is required");
    const {rows: [post]} = await query(client, res, "INSERT INTO posts (author, title, content) VALUES ($1, $2, $3) RETURNING *", [userId, postName, content]);
    res.send({
        message: `Created post with name ${postName}`,
        post
    });
});
app.put("/posts/:id/edit", async (req, res) => {
    const { id } = req.params;
    const { postName, content } = req.body;
    const [,userId] = await getUserFromAuth(client, req, res);
    requireValue(postName || content, res, "At least one of post name or content is required to update");
    let query = postName ? ("title = $1" + (content ? ", content = $2" : "")) : "content = $1";
    // await queryResultOrElse(client, res, "SELECT * FROM posts WHERE user = $1 AND id = $2", [userId, id], `No post found with ID ${id}`);
    const {rows: [post]} = await queryResultOrElse(client, res, `UPDATE posts SET ${query} WHERE author = $3 AND id = $4 RETURNING *`, [postName, content, userId, id], `No post found with ID ${id}`);
    res.send({
        message: `Updated post with ID ${id} and name ${postName}`,
        post
    });
});
app.delete("/posts/:id/delete", async (req, res) => {
    const { id } = req.params;
    const [,userId] = await getUserFromAuth(client, req, res);
    // await queryResultOrElse(client, res, "SELECT * FROM posts WHERE user = $1 AND id = $2", [userId, id], `No post found with ID ${id}`);
    await queryResultOrElse(client, res, "DELETE FROM posts WHERE author = $1 AND id = $2", [userId, id], `No post found with ID ${id} for user ${name}`);
    res.send({
        message: `Deleted post with ID ${id}`
    });
});

// Posts

app.post("/users/:name/posts/create", async (req, res) => {
    const { name } = req.params;
    const { postName, content } = req.body;
    const [,userId] = await checkUserAuth(client, name, req, res, "create a post while logged in", true, () => {});
    requireValue(postName, res, "Post name is required");
    requireValue(content, res, "Content is required");
    const {rows: [post]} = await query(client, res, "INSERT INTO posts (author, title, content) VALUES ($1, $2, $3) RETURNING *", [userId, postName, content]);
    res.send({
        message: `Created post with user ${name}`,
        post
    });
});
app.get("/users/:name/posts/:id", async (req, res) => {
    const { name, id } = req.params;
    const [,userId] = await checkUserExists(client, name, res);
    const {rows: [post]} = await queryResultOrElse(client, res, "SELECT * FROM posts WHERE author = $1 AND id = $2", [userId, id], `No post found with ID ${id} for user ${name}`);
    res.send({
        message: `post user is ${name} and ID is ${id}`,
        post
    });
});
app.put("/users/:name/posts/:id/edit", async (req, res) => {
    const { name, id } = req.params;
    const { postName, content } = req.body;
    const [,userId] = await checkUserAuth(client, name, req, res, "edit a post while logged in", true);
    requireValue(postName || content, res, "At least one of post name or content is required to update");
    let query = postName ? ("title = $1" + (content ? ", content = $2" : "")) : "content = $2";
    // await queryResultOrElse(client, res, "SELECT * FROM posts WHERE user = $1 AND id = $2", [userId, id], `No post found with ID ${id} for user ${name}`);
    const {rows: [post]} = await queryResultOrElse(client, res, `UPDATE posts SET ${query} WHERE author = $3 AND id = $4 RETURNING *`, [postName, content, userId, id], `No post found with ID ${id}`);
    res.send({
        message: `Updated post with ID ${id} and name ${postName}`,
        post
    });
});
app.delete("/users/:name/posts/:id/delete", async (req, res) => {
    const { name, id } = req.params;
    const [,userId] = await checkUserAuth(client, name, req, res, "delete a post while logged in", true);
    // await queryResultOrElse(client, res, "SELECT * FROM posts WHERE user = $1 AND id = $2", [userId, id], `No post found with ID ${id}`);
    await queryResultOrElse(client, res, "DELETE FROM posts WHERE author = $1 AND id = $2", [userId, id], `No post found with ID ${id} for user ${name}`);
    res.send({
        message: `Deleted post with ID ${id}`
    });
});

// Post comments

app.get("/users/:name/posts/:id/comments", async (req, res) => {
    const { name, id } = req.params;
    const [,userId] = await checkUserExists(client, name, res);
    const {rows: comments} = await query(client, res, "SELECT * FROM comments WHERE post = $1", [id]);
    res.send({
        message: `Comments for post with ID ${id} and user ${name}`,
        comments
    });
});
// Post a comment to a post
app.post("/users/:name/posts/:id/comments/create", async (req, res) => {
    const { name, id } = req.params;
    const { content } = req.body;
    const [,,currentUserId] = await checkUserAuth(client, name, req, res, "add a comment while logged in", false);
    requireValue(content, res, "Content is required for the comment");
    const {rows: [comment]} = await query(client, res, "INSERT INTO comments (post, author, content) VALUES ($1, $2, $3) RETURNING *", [id, currentUserId, content]);
    res.send({
        message: `Comment added to post with ID ${id} and user ${name}`,
        comment
    });
});
// Get a comment by its ID (also applies to replies)
app.get("/users/:name/posts/:id/comments/:commentId", async (req, res) => {
    const { name, id, commentId } = req.params;
    await checkUserExists(client, name, res);
    let {rows: [comment]} = await queryResultOrElse(client, res, "SELECT * FROM comments WHERE post = $1 AND id = $2", [id, commentId], `No comment found with ID ${commentId} for post with ID ${id} and user ${name}`);
    res.send({
        message: `Comment with ID ${commentId} for post with ID ${id} and user ${name} found`,
        comment
    });
});
// Get all replies to a comment
app.post("/users/:name/posts/:id/comments/:commentId/reply", async (req, res) => {
    const { name, id, commentId } = req.params;
    const { content } = req.body;
    const [,,currentUserId] = await checkUserAuth(client, name, req, res, "reply to a comment while logged in", false);
    requireValue(content, res, "Content is required for the reply");
    const {rows: [reply]} = await query(client, res, "INSERT INTO comments (post, author, parent, content) VALUES ($1, $2, $3, $4) RETURNING *", [id, currentUserId, commentId, content]);
    res.send({
        message: `Reply added to comment with ID ${commentId} for post with ID ${id} and user ${name}`,
        reply
    });
});
app.get("/users/:name/posts/:id/comments/:commentId/replies", async (req, res) => {
    const { name, id, commentId } = req.params;
    await checkUserExists(client, name, res);
    const {rows: replies} = await query(client, res, "SELECT * FROM comments WHERE post = $1 AND parent = $2", [id, commentId]);
    res.send({
        message: `Replies for comment with ID ${commentId} for post with ID ${id} and user ${name}`,
        replies
    });
});
app.put("/users/:name/posts/:id/comments/:commentId/edit", async (req, res) => {
    const { name, id, commentId } = req.params;
    const { content } = req.body;
    const [,,currentUserId] = await checkUserAuth(client, name, req, res, "edit a comment while logged in", false);
    requireValue(content, res, "Content is required for the comment");
    // await queryResultOrElse(client, res, "SELECT * FROM comments WHERE post = $1 AND id = $2 AND user = $3", [id, commentId, currentUserId], `No comment found with ID ${commentId} for post with ID ${id} and user ${name}`);
    const {rows: [comment]} = await queryResultOrElse(client, res, "UPDATE comments SET content = $1 WHERE post = $2 AND id = $3 AND author = $4 RETURNING *", [content, id, commentId, currentUserId], `No comment found with ID ${commentId} for post with ID ${id} and user ${name}`);
    res.send({
        message: `Updated comment with ID ${commentId} for post with ID ${id} and user ${name}`,
        comment
    });
});
app.delete("/users/:name/posts/:id/comments/:commentId/delete", async (req, res) => {
    const { name, id, commentId } = req.params;
    const [,,currentUserId] = await checkUserAuth(client, name, req, res, "delete a comment while logged in", false);
    // await queryResultOrElse(client, res, "SELECT * FROM comments WHERE post = $1 AND id = $2 AND user = $3", [id, commentId, currentUserId], `No comment found with ID ${commentId} for post with ID ${id} and user ${name}`);
    await queryResultOrElse(client, res, "DELETE FROM comments WHERE post = $1 AND id = $2 AND author = $3", [id, commentId, currentUserId], `No comment found with ID ${commentId} for post with ID ${id} and user ${name}`);
    res.send({
        message: `Deleted comment with ID ${commentId} for post with ID ${id} and user ${name}`
    });
});


app.use("/docs", express.static("docs"));


app.listen(port, async () => {
    console.log(`Server is running at http://localhost:${port}`);
    client = await db.connect().catch(err => {
        console.error("Database connection error:", err);
        process.exit(1);
    });
    await initDatabase(client);
});
