const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const app = express();
const db = new sqlite3.Database('./tierlist.db');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS tierlists (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      type TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tierlist_id INTEGER NOT NULL,
      artist TEXT,
      title TEXT,
      image_url TEXT,
      description TEXT,
      score REAL,
      status TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(tierlist_id) REFERENCES tierlists(id)
    );
  `);
});

function findOrCreateUser(name, password, cb) {
  db.get(`SELECT * FROM users WHERE name = ?`, [name], async (err, row) => {
    if (err) return cb(err);

    if (!row) {
      try {
        const hash = await bcrypt.hash(password, 10);
        db.run(
          `INSERT INTO users (name, password_hash) VALUES (?, ?)`,
          [name, hash],
          function (err2) {
            if (err2) return cb(err2);
            cb(null, { id: this.lastID, name });
          }
        );
      } catch (e) {
        cb(e);
      }
    } else {
      const ok = await bcrypt.compare(password, row.password_hash);
      if (!ok) return cb(new Error('INVALID_PASSWORD'));
      cb(null, row);
    }
  });
}

function assertOwner(tierlistId, name, password, cb) {
  db.get(
    `
    SELECT users.*
    FROM tierlists
    JOIN users ON tierlists.user_id = users.id
    WHERE tierlists.id = ?
  `,
    [tierlistId],
    async (err, owner) => {
      if (err) return cb(err);
      if (!owner) return cb(new Error('NO_TIERLIST'));

      const ok = await bcrypt.compare(password, owner.password_hash);
      if (!ok || owner.name !== name) return cb(new Error('FORBIDDEN'));
      cb(null, owner);
    }
  );
}

app.post('/api/tierlists', (req, res) => {
  const { name, password, type, title } = req.body;
  if (!name || !password || !type || !title) {
    return res.status(400).json({ error: 'missing fields' });
  }

  findOrCreateUser(name, password, (err, user) => {
    if (err) {
      if (err.message === 'INVALID_PASSWORD') {
        return res.status(401).json({ error: 'wrong password for existing user' });
      }
      console.error(err);
      return res.status(500).json({ error: 'server error' });
    }

    db.run(
      `INSERT INTO tierlists (user_id, title, type) VALUES (?, ?, ?)`,
      [user.id, title, type],
      function (err2) {
        if (err2) {
          console.error(err2);
          return res.status(500).json({ error: 'server error' });
        }
        res.json({ id: this.lastID });
      }
    );
  });
});

app.get('/api/tierlists', (req, res) => {
  db.all(
    `
    SELECT tierlists.id, tierlists.title, tierlists.type, users.name AS owner
    FROM tierlists
    JOIN users ON tierlists.user_id = users.id
    ORDER BY tierlists.created_at DESC
  `,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'server error' });
      res.json(rows);
    }
  );
});

app.get('/api/tierlists/:id', (req, res) => {
  const id = req.params.id;

  db.get(
    `
    SELECT tierlists.id, tierlists.title, tierlists.type, users.name AS owner
    FROM tierlists
    JOIN users ON tierlists.user_id = users.id
    WHERE tierlists.id = ?
  `,
    [id],
    (err, tl) => {
      if (err) return res.status(500).json({ error: 'server error' });
      if (!tl) return res.status(404).json({ error: 'not found' });

      db.all(
        `
        SELECT * FROM items
        WHERE tierlist_id = ?
        ORDER BY score DESC NULLS LAST, created_at ASC
      `,
        [id],
        (err2, items) => {
          if (err2) return res.status(500).json({ error: 'server error' });
          res.json({ tierlist: tl, items });
        }
      );
    }
  );
});

app.post('/api/tierlists/:id/items', (req, res) => {
  const tierlistId = req.params.id;
  const { name, password, artist, title, imageUrl, description } = req.body;

  if (!name || !password || !title) {
    return res.status(400).json({ error: 'missing fields' });
  }

  assertOwner(tierlistId, name, password, (err) => {
    if (err) {
      if (err.message === 'FORBIDDEN') return res.status(403).json({ error: 'forbidden' });
      if (err.message === 'NO_TIERLIST') return res.status(404).json({ error: 'not found' });
      console.error(err);
      return res.status(500).json({ error: 'server error' });
    }

    db.run(
      `
      INSERT INTO items (tierlist_id, artist, title, image_url, description, score, status)
      VALUES (?, ?, ?, ?, ?, NULL, 'waiting')
    `,
      [tierlistId, artist || '', title, imageUrl || '', description || ''],
      function (err2) {
        if (err2) {
          console.error(err2);
          return res.status(500).json({ error: 'server error' });
        }
        res.json({ id: this.lastID });
      }
    );
  });
});

app.patch('/api/items/:id', (req, res) => {
  const itemId = req.params.id;
  const { name, password, score, status, description } = req.body;

  if (!name || !password) {
    return res.status(400).json({ error: 'missing auth' });
  }

  db.get(`SELECT * FROM items WHERE id = ?`, [itemId], (err, item) => {
    if (err) return res.status(500).json({ error: 'server error' });
    if (!item) return res.status(404).json({ error: 'not found' });

    assertOwner(item.tierlist_id, name, password, (err2) => {
      if (err2) {
        if (err2.message === 'FORBIDDEN') return res.status(403).json({ error: 'forbidden' });
        if (err2.message === 'NO_TIERLIST') return res.status(404).json({ error: 'not found' });
        console.error(err2);
        return res.status(500).json({ error: 'server error' });
      }

      const newScore = typeof score === 'number' ? score : item.score;
      const newStatus = status || item.status;
      const newDesc = typeof description === 'string' ? description : item.description;

      db.run(
        `
        UPDATE items
        SET score = ?, status = ?, description = ?
        WHERE id = ?
      `,
        [newScore, newStatus, newDesc, itemId],
        function (err3) {
          if (err3) {
            console.error(err3);
            return res.status(500).json({ error: 'server error' });
          }
          res.json({ ok: true });
        }
      );
    });
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
