import { compareSync } from "bcrypt";
import { Response } from "express";
import fs from "fs";
import jwt from "jsonwebtoken"
import * as pg from "pg";

export async function initDatabase(client: pg.PoolClient) {
    return client.query(`
        CREATE TABLE IF NOT EXISTS users (
            id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL UNIQUE,
            password VARCHAR(100) NOT NULL,
            api_key VARCHAR(100) NOT NULL UNIQUE
        );
    `).catch(err => {
        console.error("Error creating users table", err);
    });
}

const PRIVATE_KEY = fs.readFileSync("private.key", "utf8");
const PUBLIC_KEY = fs.readFileSync("public.key", "utf8");
export function generateJwt(payload: string | object): string {
    return jwt.sign(payload, PRIVATE_KEY, { algorithm: "RS256", expiresIn: "1h" });
}

export function dbError(res: Response, err: any) {
    console.error("Error executing query", err);
    res.status(500).send({
        message: "Internal server error"
    });
}

export function checkUser(client: pg.ClientBase, name: string, res: Response, fulfill: (result: pg.QueryResult) => void | PromiseLike<void>) {
    client.query("SELECT * FROM users WHERE name = $1", [name]).then(result => {
        if (result.rows.length === 0) {
            res.status(404).send({
                error: `No user found with name ${name}`
            });
            return;
        }
        fulfill(result);
    }, err => dbError(res, err));
}
export function checkUserAccountAuth(client: pg.ClientBase, name: string, password: string, res: Response, fulfill: (result: pg.QueryResult, id: string) => void | PromiseLike<void>) {
    client.query("SELECT * FROM users WHERE name = $1", [name]).then(result => {
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
    }, err => dbError(res, err));
}
