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

// ==========================================
// ROUTES PRODUITS
// ==========================================

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
    if (err) return res.status(500).json({ error: "Erreur lors de l'ajout du produit" });
    res.status(201).json({ message: 'Produit ajouté avec succès !', productId: result.insertId });
  });
});

app.put('/api/products/:id', (req, res) => {
  const { id } = req.params;
  const { name, category, price, description, image_url, stock } = req.body;
  db.query('UPDATE products SET name = ?, category = ?, price = ?, description = ?, image_url = ?, stock = ? WHERE id = ?', 
    [name, category, price, description, image_url, stock, id], (err) => {
    if (err) return res.status(500).json({ error: "Erreur lors de la modification" });
    res.json({ message: 'Produit mis à jour avec succès !' });
  });
});

app.delete('/api/products/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM products WHERE id = ?', [id], (err) => {
    if (err) return res.status(500).json({ error: "Erreur lors de la suppression" });
    res.json({ message: 'Produit supprimé avec succès !' });
  });
});


// ==========================================
// AUTHENTIFICATION & UTILISATEURS
// ==========================================

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

// Connexion avec vérification de blocage et message orienté Super Admin
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0) return res.status(401).json({ error: "Email ou mot de passe incorrect." });

    const user = results[0];

    if (user.status === 'blocked') {
      return res.status(403).json({ 
        error: "Accès refusé : Votre compte a été suspendu ou bloqué par l'administration.",
        support: "Pour plus d'informations ou pour contester cette décision, veuillez contacter directement le Super Administrateur à l'adresse : support@techsetup.com ou par téléphone au +243 000 000 000."
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

// Route Mot de passe oublié
app.post('/api/forgot-password', async (req, res) => {
  const { email, newPassword } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: "Aucun compte associé à cet email." });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    db.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email], (err) => {
      if (err) return res.status(500).json({ error: "Erreur lors de la réinitialisation." });
      res.json({ message: "Mot de passe réinitialisé avec succès ! Vous pouvez vous connecter." });
    });
  });
});

// Modification du mot de passe (Compte connecté)
app.put('/api/user/password', async (req, res) => {
  const { userId, oldPassword, newPassword } = req.body;
  db.query('SELECT * FROM users WHERE id = ?', [userId], async (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: "Utilisateur non trouvé." });

    const user = results[0];
    const match = await bcrypt.compare(oldPassword, user.password);
    if (!match) return res.status(401).json({ error: "Ancien mot de passe incorrect." });

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    db.query('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, userId], (err) => {
      if (err) return res.status(500).json({ error: "Erreur lors de la mise à jour." });
      res.json({ message: "Mot de passe mis à jour avec succès !" });
    });
  });
});


// ==========================================
// COMMANDES & FIDÉLITÉ
// ==========================================

app.post('/api/orders', (req, res) => {
  const { userId, cartItems, totalAmount } = req.body;

  db.beginTransaction((err) => {
    if (err) return res.status(500).json({ error: "Erreur transaction" });

    db.query('INSERT INTO orders (user_id, total_amount) VALUES (?, ?)', [userId, totalAmount], (err, result) => {
      if (err) return db.rollback(() => res.status(500).json({ error: "Erreur création commande" }));
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
            res.status(201).json({ message: "Commande validée avec succès !" });
          });
        })
        .catch(() => {
          db.rollback(() => res.status(500).json({ error: "Stock insuffisant ou erreur traitement" }));
        });
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


// ==========================================
// ESPACE ADMIN
// ==========================================

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
    if (err) return res.status(500).json({ error: "Erreur modification rôle" });
    res.json({ message: "Rôle mis à jour !" });
  });
});

app.put('/api/admin/user-status', (req, res) => {
  const { userId, newStatus } = req.body;
  db.query('UPDATE users SET status = ? WHERE id = ?', [newStatus, userId], (err) => {
    if (err) return res.status(500).json({ error: "Erreur modification statut" });
    res.json({ message: "Statut mis à jour !" });
  });
});

app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});