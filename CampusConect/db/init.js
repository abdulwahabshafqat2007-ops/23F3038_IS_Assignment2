const Database = require('better-sqlite3');
const db = new Database('db/campus.db');

db.exec(`
DROP TABLE IF EXISTS users;
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  full_name TEXT NOT NULL,
  bio TEXT DEFAULT ''
);
`);

const insert = db.prepare(`INSERT INTO users (username, password, full_name, bio) VALUES (?, ?, ?, ?)`);
insert.run('shadow', 'password123', 'Abdul Wahab', 'SWE student at FAST-NUCES.');
insert.run('alice', 'alicepass', 'Alice Khan', 'Loves databases.');
insert.run('admin', 'supersecretadmin', 'System Admin', 'Administrator account.');

console.log('Database seeded successfully.');