const bcrypt = require('bcrypt');


const motDePasseClair = '!Techsetup@Admin@Master@2026!';

bcrypt.hash(motDePasseClair, 10, (err, hash) => {
  if (err) throw err;
  console.log(hash);
});