import { compareSync } from "bcrypt";
import { NextFunction, Request, Response } from "express";
import fs from "fs";
import jwt from "jsonwebtoken"
import * as pg from "pg";

export async function initDatabase(client: pg.PoolClient) {
    await client.query(`
        CREATE TABLE IF NOT EXISTS users (
            id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL UNIQUE,
            password_hash VARCHAR(100) NOT NULL,
            api_key VARCHAR(100) NOT NULL UNIQUE
        );
    `).catch(err => console.error("Error creating users table", err));

    await client.query(`
        CREATE TABLE IF NOT EXISTS profiles (
            id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            user INT NOT NULL,
            display_name VARCHAR(100) NOT NULL,
            bio TEXT,
            about TEXT,
            profile_picture_url VARCHAR(2083),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user) REFERENCES users(id) ON DELETE CASCADE`)

    await client.query(`
        CREATE TABLE IF NOT EXISTS posts (
            id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            user INT NOT NULL,
            title VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            edited_at TIMESTAMP,
            FOREIGN KEY (user) REFERENCES users(id) ON DELETE CASCADE
        );
    `).catch(err => console.error("Error creating posts table", err));

    await client.query(`
        CREATE TABLE IF NOT EXISTS comments (
            id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            post INT NOT NULL,
            user INT NOT NULL,
            parent INT,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            edited_at TIMESTAMP,
            FOREIGN KEY (post) REFERENCES posts(id) ON DELETE CASCADE,
            FOREIGN KEY (user) REFERENCES users(id) ON DELETE CASCADE,
        );
    `).catch(err => console.error("Error creating comments table", err));

    await client.query(`
        CREATE TABLE IF NOT EXISTS user_comments (
            id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            user_page INT NOT NULL,
            user INT NOT NULL,
            parent INT,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            edited_at TIMESTAMP,
            FOREIGN KEY (user_page) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (user) REFERENCES users(id) ON DELETE CASCADE,
        );
    `).catch(err => console.error("Error creating user_comments table", err));
}

export function dbError(res: Response, err: any) {
    console.error("Error executing query", err);
    res.status(500).send({
        message: "Internal server error"
    });
}
export function query(client: pg.ClientBase, res: Response, text: string, fulfill?: (result: pg.QueryResult) => void | PromiseLike<void>): Promise<pg.QueryResult | void>;
export function query(client: pg.ClientBase, res: Response, text: string, params: any[], fulfill?: (result: pg.QueryResult) => void | PromiseLike<void>): Promise<pg.QueryResult | void>;
export function query(client: pg.ClientBase, res: Response, text: string, params?: any[] | ((result: pg.QueryResult) => void | PromiseLike<void>), fulfill?: (result: pg.QueryResult) => void | PromiseLike<void>): Promise<pg.QueryResult | void> {
    if (typeof params === "function") {
        fulfill = params;
        params = undefined;
    }
    return client.query(text, params).then(fulfill, err => dbError(res, err));
}

export function checkUserExists(client: pg.ClientBase, name: string, res: Response, fulfill: (result: pg.QueryResult, id: string) => void | PromiseLike<void>) {
    query(client, res, "SELECT * FROM users WHERE name = $1", [name], result => {
        if (result.rows.length === 0) {
            res.status(404).send({
                error: `No user found with name ${name}`
            });
            return;
        }
        fulfill(result, String(result.rows[0].id));
    });
}
export function checkUserAccountAuth(client: pg.ClientBase, name: string, password: string, res: Response, fulfill: (result: pg.QueryResult, id: string) => void | PromiseLike<void>) {
    query(client, res, "SELECT * FROM users WHERE name = $1", [name], result => {
        if (result.rows.length === 0) {
            res.status(404).send({
                error: `No user found with name ${name}`
            });
            return;
        }
        if (!compareSync(password, result.rows[0].password_hash)) {
            res.status(401).header("WWW-Authenticate", `Basic realm="User Visible Realm"`).send({
                error: "Incorrect password"
            });
            return;
        }
        fulfill(result, String(result.rows[0].id));
    });
}

export function checkCorrectUser(res: Response, userId: string, currentUserId: string, message: string) {
    if (userId !== currentUserId) {
        res.status(403).send({
            error: `You can only ${message}`
        });
        return false;
    }
    return true;
}

export const PUBLIC_KEY = fs.readFileSync("public.key", "utf8");
const PRIVATE_KEY = fs.readFileSync("private.key", "utf8"); // Not exported, only allowed to be used here
export function generateJwt(payload: string | object): string {
    return jwt.sign(payload, PRIVATE_KEY, { algorithm: "RS256", expiresIn: "1h" });
}
export function checkAuthentication(req: Request, res: Response): string | null {
    // null = missing or invalid token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        res.status(401).header("WWW-Authenticate", `Bearer realm="User Visible Realm"`).send({
            error: "Missing token"
        });
        return null;
    }
    const token = authHeader.substring(7);
    try {
        const decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ["RS256"] }) as { userId: string };
        return decoded.userId;
    } catch (err) {
        res.status(401).header("WWW-Authenticate", `Bearer realm="User Visible Realm"`).send({
            error: "Invalid token"
        });
        return null;
    }
}
export function checkUserAuthentication(client: pg.ClientBase, name: string, req: Request, res: Response, msg: string, mustMatch: boolean, fulfill: (result: pg.QueryResult, id: string, currentId: string) => void | PromiseLike<void>) {
    checkUserExists(client, name, res, (result, userId) => {
        const currentUserId = checkAuthentication(req, res);
        if (!currentUserId) return;
        if (mustMatch && !checkCorrectUser(res, userId, currentUserId, msg)) return;
        fulfill(result, userId, currentUserId);
    });
} 