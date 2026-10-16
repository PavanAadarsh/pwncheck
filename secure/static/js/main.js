/**
 * QuickMart Storefront Client Script
 * Standard e-commerce catalog, shopping cart, and staff management interface.
 */

let currentProducts = [];
let cart = [];
let currentUser = null;

// Emoji visuals for common grocery/retail items
const PRODUCT_ICONS = {
  milk: "🥛",
  bread: "🍞",
  coffee: "☕",
  tea: "🍵",
  biscuit: "🍪",
  apple: "🍎",
  banana: "🍌",
  rice: "🍚",
  wheat: "🌾",
  sugar: "🍬",
  monitor: "🖥️",
  laptop: "💻",
  mouse: "🖱️",
  keyboard: "⌨️",
  headphones: "🎧",
  soap: "🧼",
  shampoo: "🧴",
  towel: "🧺"
};

function getProductIcon(name) {
  if (!name) return "📦";
  const lower = name.toLowerCase();
  for (const [key, icon] of Object.entries(PRODUCT_ICONS)) {
    if (lower.includes(key)) return icon;
  }
  return "📦";
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ---------------------------------------------------------------------------
// Toast Notification
// ---------------------------------------------------------------------------
function showToast(message) {
  const toast = document.getElementById("toast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add("show");
  setTimeout(() => {
    toast.classList.remove("show");
  }, 3000);
}

// ---------------------------------------------------------------------------
// Modal Controllers
// ---------------------------------------------------------------------------
function openModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add("open");
}

function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove("open");
}

// Close modals when clicking overlay background
document.addEventListener("click", (e) => {
  if (e.target.classList.contains("modal-overlay")) {
    e.target.classList.remove("open");
  }
});

// ---------------------------------------------------------------------------
// Product Catalog & Search
// ---------------------------------------------------------------------------
async function loadProducts() {
  const grid = document.getElementById("products-grid");
  const countEl = document.getElementById("product-count");
  const titleEl = document.getElementById("catalog-title");

  try {
    const res = await fetch("/products");
    const data = await res.json();
    currentProducts = data;
    titleEl.textContent = "All Products";
    countEl.textContent = `${data.length} products available`;
    renderProducts(data);
  } catch (err) {
    grid.innerHTML = `<div class="empty-state">Unable to load catalog products.</div>`;
  }
}

function renderProducts(items) {
  const grid = document.getElementById("products-grid");
  if (!items || items.length === 0) {
    grid.innerHTML = `<div class="empty-state">No products found matching your search.</div>`;
    return;
  }

  grid.innerHTML = items.map((item) => {
    const icon = getProductIcon(item.name);
    const priceDisplay = (typeof item.price === "number") ? item.price.toFixed(2) : item.price;
    return `
      <div class="product-card">
        <div class="product-visual">${icon}</div>
        <div class="product-details">
          <div class="product-name">${escapeHtml(item.name)}</div>
          <div class="product-price">₹${escapeHtml(priceDisplay)}</div>
          <button class="btn-add" onclick="addToCart('${escapeHtml(item.name)}', ${item.price})">
            Add to Cart
          </button>
        </div>
      </div>
    `;
  }).join("");
}

async function handleSearch(e) {
  e.preventDefault();
  const q = document.getElementById("search-input").value.trim();
  const titleEl = document.getElementById("catalog-title");
  const countEl = document.getElementById("product-count");

  if (!q) {
    loadProducts();
    return;
  }

  try {
    const res = await fetch(`/products/search?q=${encodeURIComponent(q)}`);
    const data = await res.json();
    titleEl.textContent = `Search: "${q}"`;
    countEl.textContent = `${data.length} result(s) found`;
    renderProducts(data);
  } catch (err) {
    // If request fails (e.g. 500 error from malformed SQL), show empty state
    document.getElementById("products-grid").innerHTML = `
      <div class="empty-state">Search encountered an error. Please try another search term.</div>
    `;
  }
}

// ---------------------------------------------------------------------------
// Shopping Cart
// ---------------------------------------------------------------------------
function addToCart(name, price) {
  const existing = cart.find(i => i.name === name);
  if (existing) {
    existing.qty += 1;
  } else {
    cart.push({ name, price: Number(price) || 0, qty: 1 });
  }
  updateCartBadge();
  showToast(`Added ${name} to your cart.`);
}

function updateCartBadge() {
  const badge = document.getElementById("cart-badge");
  const totalItems = cart.reduce((sum, item) => sum + item.qty, 0);
  badge.textContent = totalItems;
}

function openCart() {
  const container = document.getElementById("cart-items-container");
  const footer = document.getElementById("cart-footer");
  const totalVal = document.getElementById("cart-total-val");

  if (cart.length === 0) {
    container.innerHTML = `<p style="color: var(--text-muted); text-align: center; padding: 24px 0;">Your cart is empty.</p>`;
    footer.style.display = "none";
  } else {
    let sum = 0;
    container.innerHTML = cart.map((item, idx) => {
      const lineTotal = item.price * item.qty;
      sum += lineTotal;
      return `
        <div class="cart-item">
          <div>
            <div style="font-weight: 600;">${escapeHtml(item.name)}</div>
            <div style="font-size: 0.85rem; color: var(--text-muted);">₹${item.price.toFixed(2)} × ${item.qty}</div>
          </div>
          <div style="display: flex; align-items: center; gap: 12px;">
            <div style="font-weight: 700;">₹${lineTotal.toFixed(2)}</div>
            <button class="cart-item-remove" onclick="removeCartItem(${idx})">×</button>
          </div>
        </div>
      `;
    }).join("");
    totalVal.textContent = `₹${sum.toFixed(2)}`;
    footer.style.display = "block";
  }

  openModal("modal-cart");
}

function removeCartItem(idx) {
  cart.splice(idx, 1);
  updateCartBadge();
  openCart();
}

function handleCheckout() {
  cart = [];
  updateCartBadge();
  closeModal("modal-cart");
  showToast("Thank you for your order! Your purchase was placed successfully.");
}

// ---------------------------------------------------------------------------
// User Session & Navigation
// ---------------------------------------------------------------------------
async function checkSession() {
  try {
    const res = await fetch("/session");
    const data = await res.json();
    currentUser = data;
    renderUserNavigation(data);
  } catch (err) {
    console.error("Failed to check session", err);
  }
}

function renderUserNavigation(sessionData) {
  const userBtnLabel = document.getElementById("user-menu-label");
  const staffToolbar = document.getElementById("staff-toolbar");
  const staffLinks = document.getElementById("staff-links");
  const staffTitle = document.getElementById("staff-portal-title");

  if (!sessionData || !sessionData.logged_in) {
    userBtnLabel.textContent = "Sign In";
    staffToolbar.style.display = "none";
    return;
  }

  const role = sessionData.role;
  const username = sessionData.username || "Account";

  if (role === "customer") {
    userBtnLabel.textContent = sessionData.profile?.name || username;
    staffToolbar.style.display = "none";
  } else if (role === "employee") {
    userBtnLabel.textContent = username;
    staffToolbar.style.display = "block";
    staffTitle.textContent = "Store Staff Portal";
    staffLinks.innerHTML = `
      <button class="staff-link-btn" onclick="openStaffRestock()">Inventory Restock</button>
      <button class="staff-link-btn" onclick="handleLogout()">Sign Out</button>
    `;
  } else if (role === "admin") {
    userBtnLabel.textContent = username;
    staffToolbar.style.display = "block";
    staffTitle.textContent = "Store Administration";
    staffLinks.innerHTML = `
      <button class="staff-link-btn" onclick="openAdminPrice()">Price Management</button>
      <button class="staff-link-btn" onclick="openAdminCustomers()">Customer Accounts</button>
      <button class="staff-link-btn" onclick="openStaffRestock()">Inventory Restock</button>
      <button class="staff-link-btn" onclick="handleLogout()">Sign Out</button>
    `;
  }
}

function handleUserMenuClick() {
  if (!currentUser || !currentUser.logged_in) {
    document.getElementById("login-error").style.display = "none";
    openModal("modal-login");
  } else if (currentUser.role === "customer") {
    // Show Customer Account Profile
    const prof = currentUser.profile || {};
    document.getElementById("prof-name").textContent = prof.name || currentUser.username;
    document.getElementById("prof-user").textContent = "@" + (prof.username || currentUser.username);
    document.getElementById("prof-mobile").textContent = prof.mobile || "Not provided";
    openModal("modal-customer-profile");
  } else {
    // Staff/Admin clicked profile icon: prompt sign out
    handleLogout();
  }
}

// ---------------------------------------------------------------------------
// Login & Logout
// ---------------------------------------------------------------------------
async function handleLogin(e) {
  e.preventDefault();
  const usernameInput = document.getElementById("login-username");
  const passwordInput = document.getElementById("login-password");
  const totpInput = document.getElementById("login-totp");
  const errBox = document.getElementById("login-error");

  errBox.style.display = "none";

  try {
    const res = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: usernameInput.value.trim(),
        password: passwordInput.value,
        totp_code: totpInput ? totpInput.value.trim() : ""
      })
    });

    const data = await res.json();
    if (res.ok && data.status === "ok") {
      closeModal("modal-login");
      usernameInput.value = "";
      passwordInput.value = "";
      if (totpInput) totpInput.value = "";
      showToast(`Welcome back, ${data.name || data.username}!`);
      await checkSession();
    } else {
      errBox.textContent = data.error || "Invalid username or password.";
      errBox.style.display = "block";
    }
  } catch (err) {
    errBox.textContent = "Unable to connect to server. Please try again.";
    errBox.style.display = "block";
  }
}

async function handleLogout() {
  try {
    await fetch("/logout");
    currentUser = null;
    closeModal("modal-customer-profile");
    await checkSession();
    showToast("You have been signed out.");
  } catch (err) {
    window.location.reload();
  }
}

// ---------------------------------------------------------------------------
// Forgot Password Flow
// ---------------------------------------------------------------------------
function openForgotPassword() {
  closeModal("modal-login");
  const msgBox = document.getElementById("reset-msg");
  msgBox.style.display = "none";
  document.getElementById("reset-username").value = "";
  document.getElementById("reset-question").value = "";
  document.getElementById("reset-answer").value = "";
  document.getElementById("reset-new-password").value = "";
  openModal("modal-reset");
}

let questionDebounceTimer = null;
function fetchSecurityQuestion(username) {
  clearTimeout(questionDebounceTimer);
  const qInput = document.getElementById("reset-question");
  if (!username.trim()) {
    qInput.value = "";
    return;
  }

  questionDebounceTimer = setTimeout(async () => {
    try {
      const res = await fetch(`/employee/security-question/${encodeURIComponent(username.trim())}`);
      const data = await res.json();
      qInput.value = data.question || "What is your mother's maiden name?";
    } catch (err) {
      qInput.value = "What is your mother's maiden name?";
    }
  }, 300);
}

async function handlePasswordReset(e) {
  e.preventDefault();
  const username = document.getElementById("reset-username").value.trim();
  const answer = document.getElementById("reset-answer").value.trim();
  const newPassword = document.getElementById("reset-new-password").value;
  const msgBox = document.getElementById("reset-msg");

  try {
    const res = await fetch("/employee/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: username,
        answer: answer,
        new_password: newPassword
      })
    });

    const data = await res.json();
    if (res.ok && data.status === "password reset") {
      msgBox.className = "msg-box success";
      msgBox.textContent = "Password reset successfully. You can now sign in.";
      msgBox.style.display = "block";
      setTimeout(() => {
        closeModal("modal-reset");
        openModal("modal-login");
      }, 1500);
    } else {
      msgBox.className = "msg-box error";
      msgBox.textContent = data.error || "Failed to reset password.";
      msgBox.style.display = "block";
    }
  } catch (err) {
    msgBox.className = "msg-box error";
    msgBox.textContent = "Server error occurred. Please try again.";
    msgBox.style.display = "block";
  }
}

// ---------------------------------------------------------------------------
// Admin Features
// ---------------------------------------------------------------------------
function openAdminPrice() {
  const statusBox = document.getElementById("price-status");
  statusBox.style.display = "none";
  document.getElementById("update-product-name").value = "";
  document.getElementById("update-product-price").value = "";
  openModal("modal-admin-price");
}

async function handlePriceUpdate(e) {
  e.preventDefault();
  const name = document.getElementById("update-product-name").value.trim();
  const price = parseFloat(document.getElementById("update-product-price").value);
  const statusBox = document.getElementById("price-status");

  try {
    const res = await fetch("/admin/update-price", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, price })
    });

    const data = await res.json();
    if (res.ok && data.status === "success") {
      statusBox.className = "msg-box success";
      statusBox.textContent = `Updated successfully (${data.rows_affected} product(s) modified).`;
      statusBox.style.display = "block";
      loadProducts();
    } else {
      statusBox.className = "msg-box error";
      statusBox.textContent = data.error || "Failed to update price.";
      statusBox.style.display = "block";
    }
  } catch (err) {
    statusBox.className = "msg-box error";
    statusBox.textContent = "Error updating price.";
    statusBox.style.display = "block";
  }
}

async function openAdminCustomers() {
  const tbody = document.getElementById("admin-customers-tbody");
  const statusBox = document.getElementById("cust-admin-status");
  statusBox.style.display = "none";
  tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding: 16px;">Loading accounts...</td></tr>`;
  openModal("modal-admin-customers");

  try {
    const res = await fetch("/admin/customers");
    const data = await res.json();
    if (res.ok && Array.isArray(data)) {
      tbody.innerHTML = data.map(cust => `
        <tr>
          <td>${cust.id}</td>
          <td style="font-weight: 600;">${escapeHtml(cust.name)}</td>
          <td>${escapeHtml(cust.mobile)}</td>
          <td>@${escapeHtml(cust.username)}</td>
        </tr>
      `).join("");
    } else {
      tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color: var(--danger); padding: 16px;">${data.error || "Unauthorized"}</td></tr>`;
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color: var(--danger); padding: 16px;">Error loading customer list.</td></tr>`;
  }
}

// ---------------------------------------------------------------------------
// Staff Restock Feature
// ---------------------------------------------------------------------------
function openStaffRestock() {
  const select = document.getElementById("restock-product-select");
  const statusBox = document.getElementById("restock-status");
  statusBox.style.display = "none";

  select.innerHTML = currentProducts.map(p => `
    <option value="${p.id}">${escapeHtml(p.name)} (ID: ${p.id})</option>
  `).join("");

  openModal("modal-staff-restock");
}

async function handleRestock(e) {
  e.preventDefault();
  const select = document.getElementById("restock-product-select");
  const qtyInput = document.getElementById("restock-qty");
  const statusBox = document.getElementById("restock-status");

  const productId = parseInt(select.value, 10);
  const qty = parseInt(qtyInput.value, 10);

  try {
    const res = await fetch("/product/bulk-update", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ product_id: productId, quantity: qty })
    });

    const data = await res.json();
    if (res.ok && data.status === "updated") {
      statusBox.className = "msg-box success";
      statusBox.textContent = `Stock batch updated successfully (${data.iterations} units processed).`;
      statusBox.style.display = "block";
    } else {
      statusBox.className = "msg-box error";
      statusBox.textContent = data.error || "Failed to process stock update.";
      statusBox.style.display = "block";
    }
  } catch (err) {
    statusBox.className = "msg-box error";
    statusBox.textContent = "Server error while processing batch update.";
    statusBox.style.display = "block";
  }
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  loadProducts();
  checkSession();
});
