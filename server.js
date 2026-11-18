const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'techsetup_db'
});

db.connect((err) => {
  if (err) {
    console.error('Erreur de connexion MySQL :', err);
    return;
  }
  console.log('Connecté à la base de données MySQL avec succès !');
});

// ================= PRODUITS =================
app.get('/api/products', (req, res) => {
  db.query('SELECT * FROM products', (err, results) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    res.json(results);
  });
});

app.post('/api/products', (req, res) => {
  const { name, category, price, description, image_url, stock } = req.body;
  const productStock = stock || 10;
  db.query('INSERT INTO products (name, category, price, description, image_url, stock) VALUES (?, ?, ?, ?, ?, ?)', 
    [name, category, price, description, image_url, productStock], (err, result) => {
    if (err) return res.status(500).json({ error: "Erreur ajout produit" });
    res.status(201).json({ message: 'Produit ajouté !', productId: result.insertId });
  });
});

app.put('/api/products/:id', (req, res) => {
  const { id } = req.params;
  const { name, category, price, description, image_url, stock } = req.body;
  db.query('UPDATE products SET name = ?, category = ?, price = ?, description = ?, image_url = ?, stock = ? WHERE id = ?', 
    [name, category, price, description, image_url, stock, id], (err) => {
    if (err) return res.status(500).json({ error: "Erreur modification" });
    res.json({ message: 'Produit mis à jour !' });
  });
});

app.delete('/api/products/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM products WHERE id = ?', [id], (err) => {
    if (err) return res.status(500).json({ error: "Erreur suppression" });
    res.json({ message: 'Produit supprimé !' });
  });
});

// ================= AUTHENTIFICATION =================
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query('INSERT INTO users (name, email, password, role, status) VALUES (?, ?, ?, "client", "active")', 
      [name, email, hashedPassword], (err) => {
      if (err) return res.status(500).json({ error: "Cet email est déjà utilisé." });
      res.status(201).json({ message: 'Compte créé avec succès !' });
    });
  } catch (error) {
    res.status(500).json({ error: "Erreur serveur." });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0) return res.status(401).json({ error: "Email ou mot de passe incorrect." });

    const user = results[0];

    if (user.status === 'blocked') {
      return res.status(403).json({ 
        error: "Accès refusé : Votre compte a été suspendu ou bloqué par l'administration.",
        support: "Pour plus d'informations, veuillez contacter le Super Administrateur à support@techsetup.com ou au +243 000 000 000."
      });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Email ou mot de passe incorrect." });

    res.json({
      message: 'Connexion réussie',
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  });
});

app.post('/api/forgot-password', async (req, res) => {
  const { email, newPassword } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: "Aucun compte associé à cet email." });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    db.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email], (err) => {
      if (err) return res.status(500).json({ error: "Erreur réinitialisation." });
      res.json({ message: "Mot de passe réinitialisé avec succès !" });
    });
  });
});

app.put('/api/user/password', async (req, res) => {
  const { userId, oldPassword, newPassword } = req.body;
  db.query('SELECT * FROM users WHERE id = ?', [userId], async (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: "Utilisateur non trouvé." });

    const user = results[0];
    const match = await bcrypt.compare(oldPassword, user.password);
    if (!match) return res.status(401).json({ error: "Ancien mot de passe incorrect." });

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    db.query('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, userId], (err) => {
      if (err) return res.status(500).json({ error: "Erreur mise à jour." });
      res.json({ message: "Mot de passe mis à jour avec succès !" });
    });
  });
});

// ================= RÉSERVATIONS (10% min, délai 72h) =================
app.post('/api/reservations', (req, res) => {
  const { userId, productId, productName, totalPrice, depositPaid } = req.body;
  const priceNum = Number(totalPrice);
  const depositNum = Number(depositPaid);
  const minDeposit = priceNum * 0.10;

  if (depositNum < minDeposit) {
    return res.status(400).json({ error: `L'acompte minimum requis est de 10%, soit $${minDeposit.toFixed(2)}.` });
  }
  if (depositNum > priceNum) {
    return res.status(400).json({ error: "L'acompte ne peut pas dépasser le prix total du produit." });
  }

  // Vérifier le stock disponible et décrémenter
  db.query('SELECT stock FROM products WHERE id = ?', [productId], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: "Produit introuvable." });
    if (results[0].stock <= 0) return res.status(400).json({ error: "Ce produit est en rupture de stock." });

    const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000); // +72 heures

    db.beginTransaction((err) => {
      if (err) return res.status(500).json({ error: "Erreur transaction." });

      db.query(
        'INSERT INTO reservations (user_id, product_id, product_name, total_price, deposit_paid, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
        [userId, productId, productName, priceNum, depositNum, expiresAt],
        (err, result) => {
          if (err) return db.rollback(() => res.status(500).json({ error: "Erreur lors de l'enregistrement de la réservation." }));

          db.query('UPDATE products SET stock = stock - 1 WHERE id = ?', [productId], (err) => {
            if (err) return db.rollback(() => res.status(500).json({ error: "Erreur mise à jour stock." }));

            db.commit((err) => {
              if (err) return db.rollback(() => res.status(500).json({ error: "Erreur validation." }));
              res.status(201).json({
                message: "Réservation confirmée ! Vous avez 72h (3 jours) pour solder le reste du montant.",
                reservationId: result.insertId,
                expiresAt
              });
            });
          });
        }
      );
    });
  });
});

app.get('/api/reservations/:userId', (req, res) => {
  const { userId } = req.params;
  const now = new Date();

  // Vérifier les réservations expirées (> 72h) et remettre en stock si besoin
  db.query("SELECT * FROM reservations WHERE status = 'active' AND expires_at < ?", [now], (err, expiredList) => {
    if (!err && expiredList && expiredList.length > 0) {
      expiredList.forEach((r) => {
        db.query("UPDATE reservations SET status = 'expired' WHERE id = ?", [r.id]);
        db.query("UPDATE products SET stock = stock + 1 WHERE id = ?", [r.product_id]);
      });
    }

    db.query('SELECT * FROM reservations WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, results) => {
      if (err) return res.status(500).json({ error: "Erreur serveur." });
      res.json(results);
    });
  });
});

// ================= COMMANDES & ADMIN =================
app.post('/api/orders', (req, res) => {
  const { userId, cartItems, totalAmount } = req.body;
  db.beginTransaction((err) => {
    if (err) return res.status(500).json({ error: "Erreur transaction" });
    db.query('INSERT INTO orders (user_id, total_amount) VALUES (?, ?)', [userId, totalAmount], (err, result) => {
      if (err) return db.rollback(() => res.status(500).json({ error: "Erreur commande" }));
      const orderId = result.insertId;
      const itemQueries = cartItems.map(item => {
        return new Promise((resolve, reject) => {
          db.query('INSERT INTO order_items (order_id, product_name, price) VALUES (?, ?, ?)', [orderId, item.name, item.price], (err) => {
            if (err) return reject(err);
            db.query('UPDATE products SET stock = stock - 1 WHERE id = ?', [item.id], (err) => {
              if (err) return reject(err);
              resolve();
            });
          });
        });
      });
      Promise.all(itemQueries)
        .then(() => {
          db.commit((err) => {
            if (err) return db.rollback(() => res.status(500).json({ error: "Erreur validation" }));
            res.status(201).json({ message: "Commande validée !" });
          });
        })
        .catch(() => db.rollback(() => res.status(500).json({ error: "Stock insuffisant" })));
    });
  });
});

app.get('/api/orders/:userId', (req, res) => {
  const { userId } = req.params;
  db.query('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, orders) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    res.json(orders);
  });
});

app.get('/api/admin/users', (req, res) => {
  const query = `
    SELECT u.id, u.name, u.email, u.role, u.status, u.created_at, 
    COUNT(o.id) AS total_orders 
    FROM users u 
    LEFT JOIN orders o ON u.id = o.user_id 
    GROUP BY u.id
  `;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    res.json(results);
  });
});

app.put('/api/admin/user-role', (req, res) => {
  const { userId, newRole } = req.body;
  db.query('UPDATE users SET role = ? WHERE id = ?', [newRole, userId], (err) => {
    if (err) return res.status(500).json({ error: "Erreur rôle" });
    res.json({ message: "Rôle mis à jour !" });
  });
});

app.put('/api/admin/user-status', (req, res) => {
  const { userId, newStatus } = req.body;
  db.query('UPDATE users SET status = ? WHERE id = ?', [newStatus, userId], (err) => {
    if (err) return res.status(500).json({ error: "Erreur statut" });
    res.json({ message: "Statut mis à jour !" });
  });
});

app.listen(PORT, () => console.log(`Serveur démarré sur le port ${PORT}`));