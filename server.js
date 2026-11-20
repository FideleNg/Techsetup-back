import express from 'express';
import cors from 'cors';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'techsetup_db',
  waitForConnections: true,
  connectionLimit: 10
});

const DEFAULT_ADMIN_PERMISSIONS = {
  can_manage_products: false,
  can_manage_orders: true,
  can_manage_cashier: false,
  can_manage_clients: false
};

const EMPTY_PERMISSIONS = {
  can_manage_products: false,
  can_manage_orders: false,
  can_manage_cashier: false,
  can_manage_clients: false
};

const SUPER_ADMIN_PERMISSIONS = {
  can_manage_products: true,
  can_manage_orders: true,
  can_manage_cashier: true,
  can_manage_clients: true
};

function parsePermissions(rawPermissions, role) {
  if (role === 'super_admin') {
    return { ...SUPER_ADMIN_PERMISSIONS };
  }
  if (role !== 'admin') {
    return { ...EMPTY_PERMISSIONS };
  }

  let parsed = {};
  if (typeof rawPermissions === 'string') {
    try {
      parsed = JSON.parse(rawPermissions || '{}');
    } catch {
      parsed = {};
    }
  } else if (rawPermissions && typeof rawPermissions === 'object') {
    parsed = rawPermissions;
  }

  return {
    ...DEFAULT_ADMIN_PERMISSIONS,
    can_manage_products: Boolean(
      parsed.can_manage_products ?? DEFAULT_ADMIN_PERMISSIONS.can_manage_products
    ),
    can_manage_orders: Boolean(
      parsed.can_manage_orders ?? DEFAULT_ADMIN_PERMISSIONS.can_manage_orders
    ),
    can_manage_cashier: Boolean(
      parsed.can_manage_cashier ?? DEFAULT_ADMIN_PERMISSIONS.can_manage_cashier
    ),
    can_manage_clients: Boolean(
      parsed.can_manage_clients ?? DEFAULT_ADMIN_PERMISSIONS.can_manage_clients
    )
  };
}

function sanitizeUser(userRow) {
  if (!userRow) return null;
  const { password, ...safeUser } = userRow;
  return {
    ...safeUser,
    permissions: parsePermissions(userRow.permissions, userRow.role)
  };
}

async function verifyPassword(plainPassword, storedPassword) {
  if (!plainPassword || !storedPassword) return false;
  if (String(storedPassword).startsWith('$2')) {
    return bcrypt.compare(String(plainPassword), String(storedPassword));
  }
  return String(plainPassword) === String(storedPassword);
}

// --- Helpers SQL MySQL ---
async function findUserById(userId) {
  const [rows] = await pool.query(
    `SELECT id, name, email, password, role, status, permissions
     FROM users
     WHERE id = ?
     LIMIT 1`,
    [userId]
  );
  return rows[0] || null;
}

async function findUserByEmail(email) {
  const normalizedEmail = String(email || '').trim().toLowerCase();
  const [rows] = await pool.query(
    `SELECT id, name, email, password, role, status, permissions
     FROM users
     WHERE LOWER(TRIM(email)) = ?
     LIMIT 1`,
    [normalizedEmail]
  );
  return rows[0] || null;
}

async function updateUserRoleAndPermissions(targetUserId, newRole, permissionsObj) {
  await pool.query(
    `UPDATE users
     SET role = ?,
         permissions = ?
     WHERE id = ?`,
    [newRole, JSON.stringify(permissionsObj), targetUserId]
  );
  return findUserById(targetUserId);
}

async function updateUserPermissionsOnly(targetUserId, permissionsObj) {
  await pool.query(
    `UPDATE users
     SET permissions = ?
     WHERE id = ?`,
    [JSON.stringify(permissionsObj), targetUserId]
  );
  return findUserById(targetUserId);
}

// --- Middlewares d'authentification et de permissions ---
async function attachUser(req, res, next) {
  try {
    const userId = req.header('x-user-id');
    if (!userId) {
      return res.status(401).json({
        error: 'Authentification requise (en-tête x-user-id manquant).'
      });
    }

    const user = await findUserById(userId);
    if (!user) {
      return res.status(401).json({ error: 'Utilisateur introuvable.' });
    }

    if (user.status === 'blocked') {
      return res.status(403).json({
        error: 'Compte bloqué.',
        support: 'Contactez le support ou un administrateur.'
      });
    }

    req.currentUser = sanitizeUser(user);
    next();
  } catch (err) {
    console.error('Erreur attachUser :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la vérification de session.' });
  }
}

function requireSuperAdmin(req, res, next) {
  if (!req.currentUser || req.currentUser.role !== 'super_admin') {
    return res.status(403).json({
      error: 'Accès refusé : action réservée exclusivement au Super Admin.'
    });
  }
  next();
}

function requirePermission(permKey) {
  return (req, res, next) => {
    const user = req.currentUser;
    if (!user) {
      return res.status(401).json({ error: 'Non authentifié.' });
    }
    if (user.role === 'super_admin') {
      return next();
    }
    if (user.role === 'admin' && Boolean(user.permissions?.[permKey])) {
      return next();
    }
    return res.status(403).json({
      error: `Accès refusé : permission "${permKey}" requise.`
    });
  };
}

// --- Authentification & gestion des mots de passe ---
app.post('/api/register', async (req, res) => {
  try {
    const cleanName = String(req.body?.name || '').trim();
    const cleanEmail = String(req.body?.email || '').trim().toLowerCase();
    const rawPassword = String(req.body?.password || '');

    if (!cleanName || !cleanEmail || rawPassword.length < 8) {
      return res.status(400).json({
        error: 'Nom, email et mot de passe (8 caractères minimum) sont requis.'
      });
    }

    const existing = await findUserByEmail(cleanEmail);
    if (existing) {
      return res.status(409).json({ error: 'Cet email est déjà utilisé.' });
    }

    const hashedPassword = await bcrypt.hash(rawPassword, 10);

    await pool.query(
      `INSERT INTO users (name, email, password, role, status, permissions)
       VALUES (?, ?, ?, 'client', 'active', ?)`,
      [cleanName, cleanEmail, hashedPassword, JSON.stringify(EMPTY_PERMISSIONS)]
    );

    return res.status(201).json({ message: 'Compte créé avec succès.' });
  } catch (err) {
    console.error('Erreur POST /api/register :', err);
    res.status(500).json({ error: "Erreur serveur lors de l'inscription." });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const emailInput = String(req.body?.email || '').trim().toLowerCase();
    const passwordInput = String(req.body?.password || '');
    const user = await findUserByEmail(emailInput);

    const isPasswordValid = user ? await verifyPassword(passwordInput, user.password) : false;

    if (!user || !isPasswordValid) {
      return res.status(401).json({ error: 'Identifiants invalides.' });
    }

    if (user.status === 'blocked') {
      return res.status(403).json({
        error: 'Votre compte est bloqué.',
        support: 'Veuillez contacter le support pour réactiver votre accès.'
      });
    }

    return res.json({
      user: sanitizeUser(user)
    });
  } catch (err) {
    console.error('Erreur POST /api/login :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la connexion.' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const emailInput = String(req.body?.email || '').trim().toLowerCase();
    const newPassword = String(req.body?.newPassword || '');

    if (!emailInput || newPassword.length < 8) {
      return res.status(400).json({
        error: 'Email requis et nouveau mot de passe (8 caractères minimum).'
      });
    }

    const user = await findUserByEmail(emailInput);
    if (!user) {
      return res.status(404).json({ error: 'Aucun compte associé à cet email.' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id]);

    return res.json({ message: 'Mot de passe réinitialisé avec succès.' });
  } catch (err) {
    console.error('Erreur POST /api/forgot-password :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la réinitialisation.' });
  }
});

app.put('/api/user/password', attachUser, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const user = await findUserById(req.currentUser.id);

    if (!user) {
      return res.status(404).json({ error: 'Utilisateur introuvable.' });
    }

    const isOldValid = await verifyPassword(oldPassword, user.password);
    if (!isOldValid) {
      return res.status(400).json({ error: 'Ancien mot de passe incorrect.' });
    }

    if (!newPassword || String(newPassword).length < 8) {
      return res.status(400).json({
        error: 'Le nouveau mot de passe doit contenir au moins 8 caractères.'
      });
    }

    const hashedPassword = await bcrypt.hash(String(newPassword), 10);
    await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id]);

    return res.json({ message: 'Mot de passe mis à jour avec succès.' });
  } catch (err) {
    console.error('Erreur PUT /api/user/password :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la mise à jour du mot de passe.' });
  }
});

// --- Routes Super Admin ---
app.put('/api/super-admin/user-role', attachUser, requireSuperAdmin, async (req, res) => {
  try {
    const { targetUserId, newRole, permissions } = req.body;

    if (!targetUserId || !['admin', 'client'].includes(newRole)) {
      return res.status(400).json({
        error: 'Paramètres invalides : targetUserId et newRole ("admin" ou "client") sont requis.'
      });
    }

    if (String(targetUserId) === String(req.currentUser.id)) {
      return res.status(400).json({
        error: 'Vous ne pouvez pas modifier votre propre rôle.'
      });
    }

    const targetUser = await findUserById(targetUserId);
    if (!targetUser) {
      return res.status(404).json({ error: 'Utilisateur cible introuvable.' });
    }

    if (targetUser.role === 'super_admin') {
      return res.status(403).json({
        error: "Le rôle d'un Super Admin ne peut pas être modifié."
      });
    }

    const nextPermissions =
      newRole === 'admin'
        ? parsePermissions(permissions, 'admin')
        : { ...EMPTY_PERMISSIONS };

    const updatedUser = await updateUserRoleAndPermissions(
      targetUserId,
      newRole,
      nextPermissions
    );

    return res.json({
      message:
        newRole === 'admin'
          ? `${updatedUser.name} a été promu Administrateur.`
          : `Le rôle Administrateur de ${updatedUser.name} a été retiré.`,
      user: sanitizeUser(updatedUser)
    });
  } catch (err) {
    console.error('Erreur PUT /api/super-admin/user-role :', err);
    res.status(500).json({ error: 'Erreur serveur lors du changement de rôle.' });
  }
});

app.put('/api/super-admin/user-permissions', attachUser, requireSuperAdmin, async (req, res) => {
  try {
    const { targetUserId, permissions } = req.body;

    if (!targetUserId || !permissions || typeof permissions !== 'object') {
      return res.status(400).json({
        error: 'Paramètres invalides : targetUserId et un objet permissions sont requis.'
      });
    }

    const targetUser = await findUserById(targetUserId);
    if (!targetUser) {
      return res.status(404).json({ error: 'Utilisateur cible introuvable.' });
    }

    if (targetUser.role === 'super_admin') {
      return res.status(403).json({
        error: 'Les droits du Super Admin sont complets et non modifiables.'
      });
    }

    if (targetUser.role !== 'admin') {
      return res.status(400).json({
        error: "Impossible de modifier des permissions d'admin sur un compte non-admin."
      });
    }

    const sanitizedPermissions = {
      can_manage_products: Boolean(permissions.can_manage_products),
      can_manage_orders: Boolean(permissions.can_manage_orders),
      can_manage_cashier: Boolean(permissions.can_manage_cashier),
      can_manage_clients: Boolean(permissions.can_manage_clients)
    };

    const updatedUser = await updateUserPermissionsOnly(targetUserId, sanitizedPermissions);

    return res.json({
      message: `Permissions mises à jour pour ${updatedUser.name}.`,
      user: sanitizeUser(updatedUser)
    });
  } catch (err) {
    console.error('Erreur PUT /api/super-admin/user-permissions :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la mise à jour des permissions.' });
  }
});

app.delete('/api/super-admin/users/:id', attachUser, requireSuperAdmin, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const targetUserId = Number(req.params.id);

    if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
      return res.status(400).json({ error: 'Identifiant utilisateur invalide.' });
    }

    if (targetUserId === Number(req.currentUser.id)) {
      return res.status(400).json({
        error: 'Vous ne pouvez pas supprimer votre propre compte Super Admin.'
      });
    }

    const [rows] = await connection.query(
      'SELECT id, name, email, role FROM users WHERE id = ? LIMIT 1',
      [targetUserId]
    );
    const targetUser = rows[0];

    if (!targetUser) {
      return res.status(404).json({ error: 'Utilisateur introuvable.' });
    }

    if (targetUser.role === 'super_admin') {
      return res.status(403).json({
        error: 'Impossible de supprimer un compte Super Admin.'
      });
    }

    await connection.beginTransaction();
    await connection.query('DELETE FROM users WHERE id = ?', [targetUserId]);
    await connection.commit();

    return res.json({
      message: `Le compte de ${targetUser.name} (${targetUser.email}) a été supprimé.`
    });
  } catch (err) {
    await connection.rollback();
    console.error('Erreur DELETE /api/super-admin/users/:id :', err);
    if (err.code === 'ER_ROW_IS_REFERENCED_2') {
      return res.status(409).json({
        error:
          "Impossible de supprimer ce compte car il est lié à d'autres enregistrements (commandes, caisse, etc.)."
      });
    }
    return res.status(500).json({ error: 'Erreur serveur lors de la suppression du compte.' });
  } finally {
    connection.release();
  }
});

// --- Route Liste Utilisateurs ---
app.get('/api/admin/users', attachUser, async (req, res) => {
  try {
    const isSuper = req.currentUser.role === 'super_admin';
    const canManageClients = Boolean(req.currentUser.permissions?.can_manage_clients);

    if (!isSuper && !canManageClients) {
      return res.status(403).json({
        error: 'Accès refusé : permission insuffisante pour consulter les utilisateurs.'
      });
    }

    const [rows] = await pool.query(
      `SELECT u.id, u.name, u.email, u.role, u.status, u.permissions,
              COUNT(o.id) AS total_orders
       FROM users u
       LEFT JOIN orders o ON o.user_id = u.id
       GROUP BY u.id, u.name, u.email, u.role, u.status, u.permissions
       ORDER BY u.id ASC`
    );

    const users = rows.map((row) => ({
      ...sanitizeUser(row),
      total_orders: Number(row.total_orders || 0)
    }));

    return res.json(users);
  } catch (err) {
    console.error('Erreur GET /api/admin/users :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la récupération des utilisateurs.' });
  }
});

// --- Statut client (bloquer / débloquer) ---
app.put(
  '/api/admin/user-status',
  attachUser,
  requirePermission('can_manage_clients'),
  async (req, res) => {
    try {
      const { userId, newStatus } = req.body;
      if (!userId || !['active', 'blocked'].includes(newStatus)) {
        return res.status(400).json({ error: 'Paramètres invalides.' });
      }

      const target = await findUserById(userId);
      if (!target) {
        return res.status(404).json({ error: 'Utilisateur introuvable.' });
      }
      if (target.role === 'super_admin') {
        return res.status(403).json({ error: 'Impossible de bloquer un Super Admin.' });
      }

      await pool.query('UPDATE users SET status = ? WHERE id = ?', [newStatus, userId]);
      return res.json({ message: 'Statut utilisateur mis à jour.' });
    } catch (err) {
      console.error('Erreur PUT /api/admin/user-status :', err);
      res.status(500).json({ error: 'Erreur serveur.' });
    }
  }
);

// --- Commandes & Livraison (can_manage_orders) ---
app.get('/api/admin/orders', attachUser, requirePermission('can_manage_orders'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT o.*, u.name AS client_name, u.email AS client_email
       FROM orders o
       JOIN users u ON u.id = o.user_id
       ORDER BY o.created_at DESC`
    );
    return res.json(rows);
  } catch (err) {
    console.error('Erreur GET /api/admin/orders :', err);
    return res.status(500).json({ error: 'Erreur lors du chargement des commandes.' });
  }
});

app.put(
  '/api/admin/orders/:id/delivery',
  attachUser,
  requirePermission('can_manage_orders'),
  async (req, res) => {
    try {
      const orderId = req.params.id;
      const { delivery_status, delivery_address, delivery_phone, delivery_notes } = req.body;

      const allowedStatuses = ['pending', 'preparing', 'shipped', 'delivered', 'cancelled'];
      if (!allowedStatuses.includes(delivery_status)) {
        return res.status(400).json({ error: 'Statut de livraison invalide.' });
      }

      await pool.query(
        `UPDATE orders
         SET delivery_status = COALESCE(?, delivery_status),
             delivery_address = COALESCE(?, delivery_address),
             delivery_phone = COALESCE(?, delivery_phone),
             delivery_notes = COALESCE(?, delivery_notes),
             updated_by = ?
         WHERE id = ?`,
        [
          delivery_status,
          delivery_address ?? null,
          delivery_phone ?? null,
          delivery_notes ?? null,
          req.currentUser.id,
          orderId
        ]
      );

      const [rows] = await pool.query('SELECT * FROM orders WHERE id = ? LIMIT 1', [orderId]);
      if (!rows[0]) {
        return res.status(404).json({ error: 'Commande introuvable.' });
      }

      return res.json({
        message: 'Suivi de livraison mis à jour.',
        order: rows[0]
      });
    } catch (err) {
      console.error('Erreur PUT /api/admin/orders/:id/delivery :', err);
      return res.status(500).json({ error: 'Erreur lors de la mise à jour de la livraison.' });
    }
  }
);

// --- Caisse (can_manage_cashier) ---
app.get(
  '/api/admin/cashier/summary',
  attachUser,
  requirePermission('can_manage_cashier'),
  async (req, res) => {
    try {
      const [totalsRows] = await pool.query(
        `SELECT
           COALESCE(SUM(CASE WHEN type IN ('sale', 'deposit', 'balance') THEN amount ELSE 0 END), 0) AS total_in,
           COALESCE(SUM(CASE WHEN type IN ('refund', 'expense') THEN amount ELSE 0 END), 0) AS total_out
         FROM cashier_transactions`
      );

      const [transactions] = await pool.query(
        `SELECT t.*, u.name AS recorded_by_name
         FROM cashier_transactions t
         LEFT JOIN users u ON u.id = t.recorded_by
         ORDER BY t.created_at DESC
         LIMIT 50`
      );

      const totalIn = Number(totalsRows[0]?.total_in || 0);
      const totalOut = Number(totalsRows[0]?.total_out || 0);

      return res.json({
        total_in: totalIn,
        total_out: totalOut,
        net_balance: totalIn - totalOut,
        transactions
      });
    } catch (err) {
      console.error('Erreur GET /api/admin/cashier/summary :', err);
      return res.status(500).json({ error: 'Erreur lors du calcul de la caisse.' });
    }
  }
);

app.post(
  '/api/admin/cashier/transactions',
  attachUser,
  requirePermission('can_manage_cashier'),
  async (req, res) => {
    const connection = await pool.getConnection();
    try {
      const { order_id, reservation_id, type, payment_method, amount, note } = req.body;
      const validTypes = ['sale', 'deposit', 'balance', 'refund', 'expense'];
      const validMethods = ['cash', 'mobile_money', 'card', 'bank_transfer'];
      const numericAmount = Number(amount);

      if (!validTypes.includes(type) || !Number.isFinite(numericAmount) || numericAmount <= 0) {
        return res.status(400).json({ error: 'Type ou montant invalide.' });
      }

      const safeMethod = validMethods.includes(payment_method) ? payment_method : 'cash';

      await connection.beginTransaction();

      const [result] = await connection.query(
        `INSERT INTO cashier_transactions
          (order_id, reservation_id, type, payment_method, amount, note, recorded_by)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          order_id || null,
          reservation_id || null,
          type,
          safeMethod,
          numericAmount,
          note || null,
          req.currentUser.id
        ]
      );

      if (order_id) {
        const nextPaymentStatus =
          type === 'refund' ? 'refunded' : type === 'deposit' ? 'deposit_paid' : 'paid';
        await connection.query(
          'UPDATE orders SET payment_status = ?, updated_by = ? WHERE id = ?',
          [nextPaymentStatus, req.currentUser.id, order_id]
        );
      }

      await connection.commit();

      return res.status(201).json({
        id: result.insertId,
        message: 'Mouvement de caisse enregistré.'
      });
    } catch (err) {
      await connection.rollback();
      console.error('Erreur POST /api/admin/cashier/transactions :', err);
      return res.status(500).json({ error: "Erreur lors de l'enregistrement en caisse." });
    } finally {
      connection.release();
    }
  }
);

// --- Produits & stocks ---
app.get('/api/products', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM products ORDER BY id DESC');
    return res.json(rows);
  } catch (err) {
    console.error('Erreur GET /api/products :', err);
    return res.status(500).json({ error: 'Erreur lors du chargement des produits.' });
  }
});

app.post('/api/products', attachUser, requirePermission('can_manage_products'), async (req, res) => {
  try {
    const { product_type, name, category, price, description, image_url, file_url, stock } = req.body;
    const safeType = product_type === 'digital' ? 'digital' : 'physical';
    const numericPrice = Number(price);
    const numericStock = safeType === 'digital' ? 0 : Math.max(0, Number(stock ?? 0));

    if (!name || !category || !Number.isFinite(numericPrice) || numericPrice <= 0) {
      return res.status(400).json({ error: 'Nom, catégorie et prix valide sont requis.' });
    }

    const [result] = await pool.query(
      `INSERT INTO products
        (product_type, name, category, price, description, image_url, file_url, stock)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        safeType,
        String(name).trim(),
        String(category).trim(),
        numericPrice,
        description || '',
        image_url || '',
        safeType === 'digital' ? file_url || '' : null,
        numericStock
      ]
    );

    return res.status(201).json({ id: result.insertId, message: 'Article ajouté avec succès.' });
  } catch (err) {
    console.error('Erreur POST /api/products :', err);
    return res.status(500).json({ error: "Erreur lors de l'ajout de l'article." });
  }
});

app.put('/api/products/:id', attachUser, requirePermission('can_manage_products'), async (req, res) => {
  try {
    const productId = req.params.id;
    const { product_type, name, category, price, description, image_url, file_url, stock } = req.body;
    const safeType = product_type === 'digital' ? 'digital' : 'physical';
    const numericPrice = Number(price);
    const numericStock = safeType === 'digital' ? 0 : Math.max(0, Number(stock ?? 0));

    await pool.query(
      `UPDATE products
       SET product_type = ?,
           name = ?,
           category = ?,
           price = ?,
           description = ?,
           image_url = ?,
           file_url = ?,
           stock = ?
       WHERE id = ?`,
      [
        safeType,
        String(name).trim(),
        String(category).trim(),
        numericPrice,
        description || '',
        image_url || '',
        safeType === 'digital' ? file_url || '' : null,
        numericStock,
        productId
      ]
    );

    return res.json({ message: 'Article mis à jour.' });
  } catch (err) {
    console.error('Erreur PUT /api/products/:id :', err);
    return res.status(500).json({ error: "Erreur lors de la mise à jour de l'article." });
  }
});

app.delete('/api/products/:id', attachUser, requirePermission('can_manage_products'), async (req, res) => {
  try {
    await pool.query('DELETE FROM products WHERE id = ?', [req.params.id]);
    return res.json({ message: 'Article supprimé.' });
  } catch (err) {
    console.error('Erreur DELETE /api/products/:id :', err);
    return res.status(500).json({ error: "Erreur lors de la suppression de l'article." });
  }
});

app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`);
});