const express = require('express');
const path = require('path');
const fs = require('fs'); // (추가) 디스크 경로 폴더 생성용
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();

/**
 * =========================
 * SQLite on Render Disk
 * =========================
 * Render는 기본 파일시스템이 ephemeral이고,
 * persistent disk의 mount path 아래만 deploy/restart 후에도 유지됨.
 * 그래서 SQLite 파일을 반드시 /var/data 아래로 둬야 함.
 */
const DISK_PATH = '/var/data';
const DB_PATH = path.join(DISK_PATH, 'tierlist.db');

// (추가) 폴더가 없으면 생성 (로컬에서도 문제없게)
try {
  fs.mkdirSync(DISK_PATH, { recursive: true });
} catch (e) {
  console.error('[BOOT] Failed to ensure disk path:', e);
}

// (수정) DB 파일 위치를 Render Disk로 고정
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('[BOOT] Failed to open SQLite DB at:', DB_PATH, err);
  } else {
    console.log('[BOOT] Using SQLite DB at:', DB_PATH);
  }
});

// (추가) SQLite 안정성 옵션(선택이지만 Render 환경에서 도움이 됨)
db.serialize(() => {
  db.run(`PRAGMA foreign_keys=ON;`);
  db.run(`PRAGMA busy_timeout=5000;`);
  // WAL은 동시성에 유리하지만 -wal/-shm 파일도 같이 생길 수 있음(정상)
  db.run(`PRAGMA journal_mode=WAL;`);
  db.run(`PRAGMA synchronous=NORMAL;`);
});

// 관리자 비밀번호(마스터키)는 서버에만 둔다.
const ADMIN_KEY = process.env.ADMIN_KEY || 'PSMASTERKEY';

// 로그인한 관리자 세션 토큰 저장용(매 서버 프로세스마다 별도)
const adminTokens = new Set();

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

  db.run(`
    CREATE TABLE IF NOT EXISTS public_tierlists (
      tierlist_id INTEGER PRIMARY KEY,
      published_at TEXT DEFAULT CURRENT_TIMESTAMP,
      like_count INTEGER DEFAULT 0,
      FOREIGN KEY(tierlist_id) REFERENCES tierlists(id)
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS tierlist_likes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tierlist_id INTEGER NOT NULL,
      client_key TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(tierlist_id, client_key),
      FOREIGN KEY(tierlist_id) REFERENCES tierlists(id)
    );
  `);
});

// ----------------- 공통 유틸 -----------------

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

function authUser(name, password, cb) {
  db.get(`SELECT * FROM users WHERE name = ?`, [name], async (err, row) => {
    if (err) return cb(err);
    if (!row) return cb(new Error('NO_USER'));
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return cb(new Error('INVALID_PASSWORD'));
    cb(null, row);
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

function assertAdminToken(token) {
  return token && adminTokens.has(token);
}

function deleteTierlistInDb(id, cb) {
  db.serialize(() => {
    db.run(`DELETE FROM public_tierlists WHERE tierlist_id = ?`, [id], function (err0) {
      if (err0) {
        console.error(err0);
      }
    });

    db.run(`DELETE FROM tierlist_likes WHERE tierlist_id = ?`, [id], function (err0b) {
      if (err0b) console.error(err0b);
    });

    db.run(`DELETE FROM items WHERE tierlist_id = ?`, [id], function (err1) {
      if (err1) {
        console.error(err1);
        return cb(err1);
      }

      db.run(`DELETE FROM tierlists WHERE id = ?`, [id], function (err2) {
        if (err2) {
          console.error(err2);
          return cb(err2);
        }
        cb(null, this.changes); // 0이면 없는 id
      });
    });
  });
}

// ----------------- 관리자 로그인 -----------------

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body || {};
  if (!password) {
    return res.status(400).json({ error: 'missing password' });
  }
  if (password !== ADMIN_KEY) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  adminTokens.add(token);
  res.json({ token });
});

// ----------------- 티어리스트 생성/조회 -----------------

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

// 공개 티어리스트 목록 (정렬 옵션: created / likes)
app.get('/api/tierlists', (req, res) => {
  const sort = req.query.sort === 'likes' ? 'likes' : 'created';
  const orderClause =
    sort === 'likes'
      ? 'ORDER BY public_tierlists.like_count DESC, public_tierlists.published_at DESC'
      : 'ORDER BY public_tierlists.published_at DESC, tierlists.created_at DESC';

  db.all(
    `
    SELECT tierlists.id,
           tierlists.title,
           tierlists.type,
           users.name AS owner,
           public_tierlists.like_count
    FROM public_tierlists
    JOIN tierlists ON public_tierlists.tierlist_id = tierlists.id
    JOIN users ON tierlists.user_id = users.id
    ${orderClause}
  `,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'server error' });
      res.json(rows);
    }
  );
});

// 특정 유저의 티어리스트 목록 (나의 티어표)
app.post('/api/user-tierlists', (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) {
    return res.status(400).json({ error: 'missing auth' });
  }

  authUser(name, password, (err, user) => {
    if (err) {
      if (err.message === 'NO_USER' || err.message === 'INVALID_PASSWORD') {
        return res.status(401).json({ error: 'invalid credentials' });
      }
      console.error(err);
      return res.status(500).json({ error: 'server error' });
    }

    db.all(
      `
      SELECT tierlists.id, tierlists.title, tierlists.type, users.name AS owner
      FROM tierlists
      JOIN users ON tierlists.user_id = users.id
      WHERE tierlists.user_id = ?
      ORDER BY tierlists.created_at DESC
    `,
      [user.id],
      (err2, rows) => {
        if (err2) return res.status(500).json({ error: 'server error' });
        res.json(rows);
      }
    );
  });
});

// 단일 티어리스트 + 아이템
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

// MODIFY용 비밀번호 인증 (소유자 비번 또는 관리자 비번 허용)
app.post('/api/tierlists/:id/auth', (req, res) => {
  const id = req.params.id;
  const { name, password } = req.body;

  if (!name || !password) {
    return res.status(400).json({ error: 'missing auth' });
  }

  if (password === ADMIN_KEY) {
    return res.json({ ok: true, admin: true });
  }

  assertOwner(id, name, password, (err) => {
    if (err) {
      if (err.message === 'FORBIDDEN') return res.status(403).json({ error: 'forbidden' });
      if (err.message === 'NO_TIERLIST') return res.status(404).json({ error: 'not found' });
      console.error(err);
      return res.status(500).json({ error: 'server error' });
    }
    return res.json({ ok: true, admin: false });
  });
});

// 티어리스트 제목 수정 (소유자 or 관리자)
app.patch('/api/tierlists/:id', (req, res) => {
  const id = req.params.id;
  const { name, password, title } = req.body || {};

  if (!password || !title) {
    return res.status(400).json({ error: 'missing fields' });
  }

  const doUpdate = () => {
    db.run(
      `
      UPDATE tierlists
      SET title = ?
      WHERE id = ?
    `,
      [title, id],
      function (err) {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'server error' });
        }
        if (this.changes === 0) {
          return res.status(404).json({ error: 'not found' });
        }
        res.json({ ok: true });
      }
    );
  };

  if (password === ADMIN_KEY) {
    return doUpdate();
  }

  if (!name) {
    return res.status(400).json({ error: 'missing name' });
  }

  assertOwner(id, name, password, (err) => {
    if (err) {
      if (err.message === 'FORBIDDEN') return res.status(403).json({ error: 'forbidden' });
      if (err.message === 'NO_TIERLIST') return res.status(404).json({ error: 'not found' });
      console.error(err);
      return res.status(500).json({ error: 'server error' });
    }
    doUpdate();
  });
});

// ----------------- 아이템 추가/수정 -----------------

// 아이템 추가 (소유자 or 관리자)
app.post('/api/tierlists/:id/items', (req, res) => {
  const tierlistId = req.params.id;
  const { name, password, artist, title, imageUrl, description } = req.body;

  if (!password || !title) {
    return res.status(400).json({ error: 'missing fields' });
  }

  const doInsert = () => {
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
  };

  if (password === ADMIN_KEY) {
    return doInsert();
  }

  if (!name) {
    return res.status(400).json({ error: 'missing name' });
  }

  assertOwner(tierlistId, name, password, (err) => {
    if (err) {
      if (err.message === 'FORBIDDEN') return res.status(403).json({ error: 'forbidden' });
      if (err.message === 'NO_TIERLIST') return res.status(404).json({ error: 'not found' });
      console.error(err);
      return res.status(500).json({ error: 'server error' });
    }
    doInsert();
  });
});

// 아이템 수정 (점수/상태/설명; 소유자 or 관리자)
app.patch('/api/items/:id', (req, res) => {
  const itemId = req.params.id;
  const { name, password, score, status, description } = req.body;

  if (!password) {
    return res.status(400).json({ error: 'missing auth' });
  }

  db.get(`SELECT * FROM items WHERE id = ?`, [itemId], (err, item) => {
    if (err) return res.status(500).json({ error: 'server error' });
    if (!item) return res.status(404).json({ error: 'not found' });

    const proceed = () => {
      const newScore =
        typeof score === 'number' || score === null ? score : item.score;
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
    };

    if (password === ADMIN_KEY) {
      return proceed();
    }

    if (!name) {
      return res.status(400).json({ error: 'missing name' });
    }

    assertOwner(item.tierlist_id, name, password, (err2) => {
      if (err2) {
        if (err2.message === 'FORBIDDEN') return res.status(403).json({ error: 'forbidden' });
        if (err2.message === 'NO_TIERLIST') return res.status(404).json({ error: 'not found' });
        console.error(err2);
        return res.status(500).json({ error: 'server error' });
      }
      proceed();
    });
  });
});

// ----------------- 티어리스트 삭제 -----------------

app.delete('/api/tierlists/:id', (req, res) => {
  const id = req.params.id;
  const { name, password } = req.body || {};

  if (!password) {
    return res.status(400).json({ error: 'missing auth' });
  }

  const doDelete = () => {
    deleteTierlistInDb(id, (err, changes) => {
      if (err) return res.status(500).json({ error: 'server error' });
      if (changes === 0) return res.status(404).json({ error: 'not found' });
      return res.sendStatus(204);
    });
  };

  if (password === ADMIN_KEY) {
    return doDelete();
  }

  if (!name) {
    return res.status(400).json({ error: 'missing name' });
  }

  assertOwner(id, name, password, (err) => {
    if (err) {
      if (err.message === 'FORBIDDEN') return res.status(403).json({ error: 'forbidden' });
      if (err.message === 'NO_TIERLIST') return res.status(404).json({ error: 'not found' });
      console.error(err);
      return res.status(500).json({ error: 'server error' });
    }
    doDelete();
  });
});

// ----------------- 관리자용 공개/비공개 & 목록 -----------------

app.post('/api/admin/tierlists', (req, res) => {
  const { adminToken } = req.body || {};
  if (!assertAdminToken(adminToken)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  db.all(
    `
    SELECT tierlists.id,
           tierlists.title,
           tierlists.type,
           users.name AS owner,
           CASE WHEN public_tierlists.tierlist_id IS NULL THEN 0 ELSE 1 END AS isPublic,
           COALESCE(public_tierlists.like_count, 0) AS like_count
    FROM tierlists
    JOIN users ON tierlists.user_id = users.id
    LEFT JOIN public_tierlists ON public_tierlists.tierlist_id = tierlists.id
    ORDER BY tierlists.created_at DESC
  `,
    [],
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'server error' });
      }
      res.json(rows);
    }
  );
});

app.post('/api/admin/tierlists/:id/publish', (req, res) => {
  const { adminToken } = req.body || {};
  if (!assertAdminToken(adminToken)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const id = req.params.id;

  db.run(
    `
    INSERT OR IGNORE INTO public_tierlists (tierlist_id, published_at, like_count)
    VALUES (?, CURRENT_TIMESTAMP, 0)
  `,
    [id],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'server error' });
      }
      res.json({ ok: true });
    }
  );
});

app.post('/api/admin/tierlists/:id/unpublish', (req, res) => {
  const { adminToken } = req.body || {};
  if (!assertAdminToken(adminToken)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const id = req.params.id;

  db.run(
    `
    DELETE FROM public_tierlists
    WHERE tierlist_id = ?
  `,
    [id],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'server error' });
      }
      res.json({ ok: true });
    }
  );
});

// ----------------- 좋아요 기능 -----------------

// 클라이언트 키 기반으로 좋아요 토글 (1인 1번)
app.post('/api/tierlists/:id/like', (req, res) => {
  const tierlistId = parseInt(req.params.id, 10);
  const { clientKey } = req.body || {};
  if (!clientKey) {
    return res.status(400).json({ error: 'missing clientKey' });
  }

  db.get(`SELECT * FROM public_tierlists WHERE tierlist_id = ?`, [tierlistId], (err, pubRow) => {
    if (err) return res.status(500).json({ error: 'server error' });
    if (!pubRow) return res.status(404).json({ error: 'not published' });

    db.get(
      `SELECT * FROM tierlist_likes WHERE tierlist_id = ? AND client_key = ?`,
      [tierlistId, clientKey],
      (err2, likeRow) => {
        if (err2) return res.status(500).json({ error: 'server error' });

        if (likeRow) {
          db.serialize(() => {
            db.run(`DELETE FROM tierlist_likes WHERE id = ?`, [likeRow.id], function (err3) {
              if (err3) console.error(err3);
            });

            db.run(
              `
              UPDATE public_tierlists
              SET like_count = CASE WHEN like_count > 0 THEN like_count - 1 ELSE 0 END
              WHERE tierlist_id = ?
            `,
              [tierlistId],
              function (err4) {
                if (err4) {
                  console.error(err4);
                  return res.status(500).json({ error: 'server error' });
                }
                db.get(
                  `SELECT like_count FROM public_tierlists WHERE tierlist_id = ?`,
                  [tierlistId],
                  (err5, row5) => {
                    if (err5) return res.status(500).json({ error: 'server error' });
                    res.json({ liked: false, likeCount: row5 ? row5.like_count : 0 });
                  }
                );
              }
            );
          });
        } else {
          db.serialize(() => {
            db.run(
              `
              INSERT INTO tierlist_likes (tierlist_id, client_key)
              VALUES (?, ?)
            `,
              [tierlistId, clientKey],
              function (err3) {
                if (err3) {
                  if (err3.code === 'SQLITE_CONSTRAINT') {
                    return res.status(409).json({ error: 'already liked' });
                  }
                  console.error(err3);
                  return res.status(500).json({ error: 'server error' });
                }

                db.run(
                  `
                  UPDATE public_tierlists
                  SET like_count = like_count + 1
                  WHERE tierlist_id = ?
                `,
                  [tierlistId],
                  function (err4) {
                    if (err4) {
                      console.error(err4);
                      return res.status(500).json({ error: 'server error' });
                    }
                    db.get(
                      `SELECT like_count FROM public_tierlists WHERE tierlist_id = ?`,
                      [tierlistId],
                      (err5, row5) => {
                        if (err5) return res.status(500).json({ error: 'server error' });
                        res.json({ liked: true, likeCount: row5 ? row5.like_count : 0 });
                      }
                    );
                  }
                );
              }
            );
          });
        }
      }
    );
  });
});

// 해당 클라이언트가 특정 티어리스트에 좋아요 눌렀는지 확인
app.post('/api/tierlists/:id/is-liked', (req, res) => {
  const tierlistId = parseInt(req.params.id, 10);
  const { clientKey } = req.body || {};
  if (!clientKey) {
    return res.status(400).json({ error: 'missing clientKey' });
  }

  db.get(
    `SELECT like_count FROM public_tierlists WHERE tierlist_id = ?`,
    [tierlistId],
    (err, pubRow) => {
      if (err) return res.status(500).json({ error: 'server error' });
      if (!pubRow) return res.json({ liked: false, likeCount: 0 });

      db.get(
        `SELECT 1 FROM tierlist_likes WHERE tierlist_id = ? AND client_key = ?`,
        [tierlistId, clientKey],
        (err2, likeRow) => {
          if (err2) return res.status(500).json({ error: 'server error' });
          res.json({ liked: !!likeRow, likeCount: pubRow.like_count });
        }
      );
    }
  );
});

// ----------------- 서버 시작 -----------------
// Render web service는 PORT 환경변수를 주는 경우가 많음
const PORT = parseInt(process.env.PORT || '3000', 10);
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
