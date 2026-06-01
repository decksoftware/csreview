const apiKey = "sk-1234567890abcdef1234567890abcdef";
const awsKey = "AKIAIOSFODNN7EXAMPLE";
const password = "admin123";
const dbUrl = "postgresql://user:pass@localhost:5432/mydb";

const md5Hash = require('crypto').createHash('md5').update('test').digest('hex');
const sha1Hash = require('crypto').createHash('sha1').update('test').digest('hex');

const query = "SELECT * FROM users WHERE id = " + userId;
const query2 = `SELECT * FROM users WHERE name = '${userName}'`;

const html = `<div>${userInput}</div>`;
document.getElementById('output').innerHTML = userInput;

const { exec } = require('child_process');
exec('ls ' + userInput);

const data = eval(userInput);
const data2 = new Function('return ' + userInput)();

app.get('/redirect', (req, res) => {
  res.redirect(req.query.url);
});

const obj = {};
obj[userInput] = 'value';

const jwt = require('jsonwebtoken');
const token = jwt.sign({ id: 1 }, 'secret', { algorithm: 'none' });

const yaml = require('js-yaml');
const config = yaml.load(userInput);

app.use(cors({ origin: '*' }));

const pickleData = pickle.loads(user_input);

const template = `Hello ${userInput}`;

const dangerous = require('child_process').execSync('cat ' + userInput);
