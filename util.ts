import { compareSync } from "bcrypt";
import { NextFunction, Request, Response } from "express";
import fs from "fs";
import jwt, { JwtPayload } from "jsonwebtoken"
import * as pg from "pg";

export async function initDatabase(client: pg.PoolClient) {
    await client.query(`
        CREATE TABLE IF NOT EXISTS users (
            id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL UNIQUE,
            password_hash VARCHAR(100) NOT NULL
        );
    `).catch(err => console.error("Error creating users table", err));

    await client.query(`
        CREATE TABLE IF NOT EXISTS profiles (
            id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            owner INT NOT NULL,
            display_name VARCHAR(100) NOT NULL,
            bio TEXT,
            about TEXT,
            profile_picture_url VARCHAR(2083),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner) REFERENCES users(id) ON DELETE CASCADE
        );
    `).catch(err => console.error("Error creating profiles table", err));

    await client.query(`
        CREATE TABLE IF NOT EXISTS posts (
            id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            author INT NOT NULL,
            title VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            edited_at TIMESTAMP,
            FOREIGN KEY (author) REFERENCES users(id) ON DELETE CASCADE
        );
    `).catch(err => console.error("Error creating posts table", err));

    await client.query(`
        CREATE TABLE IF NOT EXISTS comments (
            id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            post INT NOT NULL,
            author INT NOT NULL,
            parent INT,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            edited_at TIMESTAMP,
            FOREIGN KEY (post) REFERENCES posts(id) ON DELETE CASCADE,
            FOREIGN KEY (author) REFERENCES users(id) ON DELETE CASCADE
        );
    `).catch(err => console.error("Error creating comments table", err));

    await client.query(`
        CREATE TABLE IF NOT EXISTS user_comments (
            id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            user_page INT NOT NULL,
            author INT NOT NULL,
            parent INT,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            edited_at TIMESTAMP,
            FOREIGN KEY (user_page) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (author) REFERENCES users(id) ON DELETE CASCADE
        );
    `).catch(err => console.error("Error creating user_comments table", err));

    console.log("Database initialized");
}

export function dbError(res: Response, err: any) {
    console.error("Error executing query", err);
    res.status(500).send({
        message: "Internal server error"
    });
}
export async function query(client: pg.ClientBase, res: Response, text: string, fulfill?: (result: pg.QueryResult) => void | PromiseLike<void>): Promise<pg.QueryResult>;
export async function query(client: pg.ClientBase, res: Response, text: string, params: any[], fulfill?: (result: pg.QueryResult) => void | PromiseLike<void>): Promise<pg.QueryResult>;
export async function query(client: pg.ClientBase, res: Response, text: string, params?: any[] | ((result: pg.QueryResult) => void | PromiseLike<void>), fulfill?: (result: pg.QueryResult) => void | PromiseLike<void>): Promise<pg.QueryResult> {
    if (typeof params === "function") {
        fulfill = params;
        params = undefined;
    }
    const result = await client.query(text, params)
    fulfill?.(result)
    return result;
}

export async function queryResultOrElse(client: pg.ClientBase, res: Response, text: string, params: any[], notFoundMessage: string | [number, string] | null, fulfill?: (result: pg.QueryResult) => void | PromiseLike<void>) {
    const result = await query(client, res, text, params, result => {
        if (result.rows.length === 0) {
            if (Array.isArray(notFoundMessage)) {
                res.status(notFoundMessage[0]).send({
                    error: notFoundMessage[1]
                });
                throw new Error(notFoundMessage[1]);
            } else {
                res.status(404).send({
                    error: notFoundMessage || "No results found"
                });
                throw new Error(notFoundMessage || "No results found");
            }
        }
    });
    fulfill?.(result);
    return result;
}

export async function checkUserExists(client: pg.ClientBase, name: string, res: Response, fulfill?: (result: pg.QueryResult, id: string) => void | PromiseLike<void>): Promise<[pg.QueryResult<any>, string]> {
    const result = await query(client, res, "SELECT * FROM users WHERE name = $1", [name]);
    if (result.rows.length === 0) {
        res.status(404).send({
            error: `No user found with name ${name}`
        });
        throw new Error(`No user found with name ${name}`);
    }
    fulfill?.(result, String(result.rows[0].id));
    return [result, String(result.rows[0].id)];
}
export async function checkUserAccountAuth(client: pg.ClientBase, name: string, password: string, res: Response, fulfill?: (result: pg.QueryResult, id: string) => void | PromiseLike<void>): Promise<[pg.QueryResult<any>, string]> {
    const result = await query(client, res, "SELECT * FROM users WHERE name = $1", [name]);
    if (result.rows.length === 0) {
        res.status(404).send({
            error: `No user found with name ${name}`
        });
        throw new Error(`No user found with name ${name}`);
    }
    if (!compareSync(password, result.rows[0].password_hash)) {
        res.status(401).header("WWW-Authenticate", `Basic realm="User Visible Realm"`).send({
            error: "Incorrect password"
        });
        throw new Error("Incorrect password");
    }
    fulfill?.(result, String(result.rows[0].id));
    return [result, String(result.rows[0].id)];
}

export function checkCorrectUser(res: Response, userId: string, currentUserId: string, message: string) {
    if (userId !== currentUserId) {
        res.status(403).send({
            error: message || "User ID does not match current user ID"
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
export function checkAuthentication(req: Request, res: Response) {
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
        const decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ["RS256"] }) as JwtPayload & { id: string, isAdmin?: boolean };
        return decoded;
    } catch (err) {
        res.status(401).header("WWW-Authenticate", `Bearer realm="User Visible Realm"`).send({
            error: "Invalid token"
        });
        return null;
    }
}

export async function checkUserAuth(client: pg.ClientBase, name: string, req: Request, res: Response, msg: string = "User ID does not match current user ID", mustMatch: boolean = false, fulfill?: (result: pg.QueryResult, id: string, currentId: string) => void | PromiseLike<void>): Promise<[pg.QueryResult<any>, string, string]> {
    const [result, userId] = await checkUserExists(client, name, res);
    const payload = checkAuthentication(req, res);
    if (!payload) throw new Error("Authentication failed");
    const {id: currentUserId, isAdmin = false} = payload;
    if (isAdmin) {
        const { actingAsUserId } = req.body;
        // Admins can act as other users by specifying actingAsUserId in the request body
        if (actingAsUserId) return [result, actingAsUserId, currentUserId];
    }
    if (mustMatch && !checkCorrectUser(res, userId, currentUserId, msg)) throw new Error(msg);
    fulfill?.(result, userId, currentUserId);
    return [result, userId, currentUserId];

}
// export async function checkUserIdAuth(client: pg.ClientBase, userId: string, req: Request, res: Response, msg: string = "User ID does not match current user ID", mustMatch?: boolean, fulfill?: (result: pg.QueryResult, id: string, currentId: string) => void | PromiseLike<void>): Promise<[pg.QueryResult<any>, string, string]> {
//     const result = await queryResultOrElse(client, res, "SELECT * FROM users WHERE id = $1", [userId], "No user found", result => {});
//     const {id: currentUserId} = checkAuthentication(req, res) ?? {};
//     if (!currentUserId) throw new Error("Authentication failed");
//     if (mustMatch && !checkCorrectUser(res, userId, currentUserId, msg)) throw new Error(msg);
//     fulfill?.(result, userId, currentUserId);
//     return [result, userId, currentUserId];
// }

export async function getUserFromAuth(client: pg.ClientBase, req: Request, res: Response, fulfill?: (result: pg.QueryResult, id: string) => void | PromiseLike<void>): Promise<[pg.QueryResult<any>, string]> {
    const {id: userId} = checkAuthentication(req, res) ?? {};
    if (!userId) {
        res.status(401).send({ error: "Invalid token" });
        throw new Error("Invalid token");
    }
    const result = await query(client, res, "SELECT * FROM users WHERE id = $1", [userId]);
    fulfill?.(result, userId);
    return [result, userId];
}

export function requireValue<T>(value: T | null | undefined, res: Response, msg: string, status: number = 400): T {
    if (value === null || value === undefined) {
        res.status(status).send({
            error: msg
        });
        throw new Error(msg);
    }
    return value;
}