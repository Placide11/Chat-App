const db = require("../utils/db");
const bycrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const register = async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bycrypt.hash(password, 10);
        const [result] = await db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            [username, hashedPassword]
        );
        const user = {
            id: result.insertId,
            username,
        };
        res.status(201).json({message: "User registered successfully", user});
    } catch (error) {
        console.error(error);
        res.status(400).json({ error: error.message });
    }
};

const login = async (req, res) => {
    try {
        const { username, password } = req.body;
        const [result] = await db.execute(
            "SELECT * FROM users WHERE username = ?",
            [username]
        );
        if (result.length === 0) {
            return res.status(401).json({ message: "User not found" });
        }
        const user = result[0];
        const passwordMatch = await bycrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: "Invalid password" });
        }
        const token = jwt.sign({ userId: user.id }, "secret", { expiresIn: "1h" });
        res.status(200).json({ message: "Login successful", token });
    } catch (error) {
        console.error(error);
        res.status(400).json({ error: error.message });
    }
};

module.exports = {
    register,
    login,
};