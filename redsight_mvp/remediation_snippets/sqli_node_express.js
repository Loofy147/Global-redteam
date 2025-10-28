// before (vulnerable)
const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;
db.query(sql, ...)

// after (remediated)
const sql = 'SELECT * FROM users WHERE id = $1';
db.query(sql, [req.query.id], ...)
