const express = require('express')
const mysql = require('mysql')
const app = express()
const bcrypt = require('bcrypt')

app.use(express.json())

var con = mysql.createConnection({
    host : "localhost",
    user : "root",
    password : "Saju@1996",
    database : "customer"
})

con.connect((err)=>{
    if(err) throw err;
    console.log('connected to database');
})

async function generateEncryptedPassword(password) {
    const saltRounds = 5;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    return hashedPassword;
  }
  
  async function validatePassword(password, encryptedPassword) {
    const isMatch = await bcrypt.compare(password, encryptedPassword);
    return isMatch;
  }
  
  app.post('/register', (req, res) => {
    const { id, first_name, last_name, courseDone, degreeLevel, Dob, createdAt, updatedAt, user_name, password } = req.body;
  
    generateEncryptedPassword(password)
      .then((hashedPassword) => {
        const query = 'INSERT INTO customer (id, first_name, last_name, courseDone, degreeLevel, Dob, createdAt, updatedAt, user_name, password) VALUES (?,?,?,?,?,?,?,?,?,?)';
        const values = [id, first_name, last_name, courseDone, degreeLevel, Dob, createdAt, updatedAt, user_name, hashedPassword];
        con.query(query, values, (err, results) => {
          if (err) {
            console.log('Error storing password:', err);
            res.status(500).json({ message: 'Error storing password' });
            return;
          }
          console.log('Password stored successfully!');
          res.status(200).json({ message: 'Password stored successfully' });
        });
      })
      .catch((err) => {
        console.error('Error generating encrypted password:', err);
        res.status(500).json({ message: 'Error generating encrypted password' });
      });
  });
  
  app.post('/login', (req, res) => {
    const { user_name, password } = req.body;
  
    const query = 'SELECT password FROM customer WHERE user_name = ?';
    con.query(query, [user_name], (err, results) => {
      if (err) {
        console.error('Error retrieving password:', err);
        res.status(500).json({ message: 'Error retrieving password' });
        return;
      }
  
      if (results.length === 0) {
        res.status(404).json({ message: 'User not found' });
        return;
      }
  
      const encryptedPasswordFromDB = results[0].password;
  
      validatePassword(password, encryptedPasswordFromDB)
        .then((isMatch) => {
          if (isMatch) {
            res.status(200).json({ message: 'Password is valid!' });
          } else {
            res.status(400).json({ message: 'Password is invalid!' });
          }
        })
        .catch((err) => {
          console.error('Error validating password:', err);
          res.status(500).json({ message: 'Error validating password' });
        });
    });
  });
  
  app.listen(3000, () => {
    console.log('Server is listening on port 3000');
  });
  
