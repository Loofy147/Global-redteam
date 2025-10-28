const fs = require('fs');

test('user query should use parameterized queries', () => {
  const code = fs.readFileSync('./src/users.js','utf8');
  expect(code).not.toMatch(/SELECT \* FROM users WHERE id = \${/);
});
