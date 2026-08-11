const { DatabaseSync } = require('node:sqlite')

const db = new DatabaseSync(':memory:')
db.exec('CREATE TABLE health (value TEXT NOT NULL)')
db.prepare('INSERT INTO health (value) VALUES (?)').run('ok')
const result = db.prepare('SELECT value FROM health').get()
db.close()

if (result?.value !== 'ok') {
  process.exitCode = 1
} else {
  console.log('sqlite-ok')
}
