🔐 Secure Password Vault

A secure, offline password manager and generator built with pure HTML, CSS, and JavaScript. This tool allows users to generate strong passwords, assess their strength, and securely store them using AES encryption — all on the client side, with no backend required.
Link:https://csr37.github.io/Kavach-X/
---

## 🚀 Features

### ✅ Password Generator
- Choose password length (8–64 characters)
- Include:
  - Uppercase letters (A–Z)
  - Lowercase letters (a–z)
  - Numbers (0–9)
  - Symbols (!@#$%^&*)
- Copy to clipboard
- Assess password strength
- Check for common password breaches (offline check)
- Placeholder for advanced online breach checking{via HIBP api}

### 🔒 Password Vault
- Secured by a **master password**
- AES-encrypted vault stored in `localStorage`
- Add, view, and manage credentials for:
  - Website/Service
  - Username/Email
  - Password
- Unlock and lock vault interface
- Copy or delete stored credentials with one click

### 🧠 Tech Stack

| Layer             | Technology / Library                       | Purpose |
|------------------|--------------------------------------------|---------|
| **Frontend**      | HTML5, CSS3, JavaScript (ES6+)             | UI and logic |
|                   | CryptoJS                                   | AES encryption |
|                   | SweetAlert2                                | Clean modals and alert popups |
|                   | Google Fonts (VT323)                       | Styling and typography |
| **Storage**       | Web `localStorage`                         | Save encrypted password data locally |

---

## 📁 File Structure

📦 Secure-Password-Vault
│
├── index.html             # Main HTML layout
├── style.css              # Styles and UI design
├── script.js              # Core logic (generation, encryption, vault)
├── common-passwords.js    # List of common weak passwords
├── README.txt             # Project documentation

---

## 🛡️ How Security Works

- **Vault Encryption**:  
  - Uses AES from CryptoJS.
  - Encrypted using the **master password** as the key.
- **Data Storage**:
  - Vault is stored in `localStorage` under the key `vaultData`.
  - No password data is stored in plain text.

> ⚠️ NOTE: This is an offline app. If you clear your browser cache/localStorage, you will lose saved passwords!

---

## 🖥️ Usage Instructions

1. **Clone the Repository**
   git clone https://github.com/your-username/secure-password-vault.git
   cd secure-password-vault

2. **Open in Browser**
   Just open `index.html` in any modern browser:
   open index.html

3. **Generate a Password**
   - Adjust settings
   - Click **Generate Password**
   - Copy and Save as needed

4. **Use the Vault**
   - Enter a **Master Password**
   - Unlock the vault
   - Add your credentials
   - Lock vault to re-encrypt data

---

## ⚙️ Future Improvements

- ☁️ Cloud sync with a secure backend (Node.js + MongoDB)
- 📱 Responsive design for mobile usability

---

## 👨‍💻 Author

**S Chandra Shekhar Raju**  
- 🌐 LinkedIn: https://www.linkedin.com/in/s-chandra-shekhar-raju-5ab7b7259/

---

## 📄 License

This project is open source and available under the MIT License.
