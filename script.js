// Password Generator + Vault Application with Offline Breach Checking
document.addEventListener('DOMContentLoaded', function() {
    // Tab functionality
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.getAttribute('data-tab');
            
            // Update active tab button
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // Update active tab content
            tabContents.forEach(content => content.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
        });
    });
    
    // Password Generator functionality
    const generateBtn = document.getElementById('generate-btn');
    const copyBtn = document.getElementById('copy-btn');
    const checkBtn = document.getElementById('check-btn');
    const saveBtn = document.getElementById('save-btn');
    const passwordField = document.getElementById('password');
    
    generateBtn.addEventListener('click', generatePassword);
    copyBtn.addEventListener('click', copyPassword);
    checkBtn.addEventListener('click', checkBreach);
    saveBtn.addEventListener('click', saveToVault);
    
    // Track clipboard timeout IDs for clearing
    const clipboardTimeouts = new Map();
    
    function generatePassword() {
        const length = parseInt(document.getElementById('length').value);
        const uppercase = document.getElementById('uppercase').checked;
        const lowercase = document.getElementById('lowercase').checked;
        const numbers = document.getElementById('numbers').checked;
        const symbols = document.getElementById('symbols').checked;
        
        if (!uppercase && !lowercase && !numbers && !symbols) {
            alert('Please select at least one character type');
            return;
        }
        
        let charset = '';
        if (uppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (lowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
        if (numbers) charset += '0123456789';
        if (symbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
        
        let password = '';
        for (let i = 0; i < length; i++) {
            const randomIndex = Math.floor(Math.random() * charset.length);
            password += charset[randomIndex];
        }
        
        passwordField.value = password;
        updateStrengthMeter(password);
    }
    
    async function copyPassword() {
        if (!passwordField.value) {
            Swal.fire('Error', 'No password to copy', 'error');
            return;
        }
    
        try {
            await navigator.clipboard.writeText(passwordField.value);
            Swal.fire({
                title: 'Copied!',
                text: 'Password copied to clipboard. It will be cleared in 10 seconds.',
                icon: 'success',
                timer: 2000
            });
            
            // Store timeout ID so we can clear it if needed
            const timeoutId = setTimeout(() => {
                clearClipboardSafely('generator-password');
                clipboardTimeouts.delete('generator-password');
            }, 10000);
            
            clipboardTimeouts.set('generator-password', timeoutId);
        } catch (err) {
            console.error('Failed to copy password:', err);
            Swal.fire('Error', 'Failed to copy password', 'error');
        }
    }
    
    async function clearClipboardSafely(context) {
        try {
            // Focus our window first
            window.focus();
            
            // Add slight delay to allow focus to take effect
            await new Promise(resolve => setTimeout(resolve, 100));
            
            // Only attempt to clear if we have focus
            if (document.hasFocus()) {
                await navigator.clipboard.writeText('Clipboard cleared by password manager');
                console.log(`Clipboard cleared (${context})`);
            } else {
                console.log(`Skipping clipboard clear - document not focused (${context})`);
            }
        } catch (err) {
            if (err.name === 'NotAllowedError') {
                console.log(`Clipboard clearing not allowed - ${err.message} (${context})`);
            } else {
                console.warn(`Clipboard clearing failed:`, err);
            }
        }
    }
    
    function updateStrengthMeter(password) {
        const meter = document.getElementById("strength-meter");
        const text = document.getElementById("strength-text");
    
        if (!meter || !text) return;
    
        meter.classList.remove("hidden");
    
        let score = 0;
        if (password.length >= 8) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[a-z]/.test(password)) score++;
        if (/\d/.test(password)) score++;
        if (/[^A-Za-z0-9]/.test(password)) score++;
        if (commonPasswords.has(password)) score = 0;
    
        let label = "Very Weak", color = "red";
        if (score >= 4) [label, color] = ["Strong", "green"];
        else if (score === 3) [label, color] = ["Medium", "orange"];
        else if (score === 2) [label, color] = ["Weak", "orangered"];
    
        text.textContent = `Strength: ${label}`;
        text.style.color = color;
    }
    
    async function checkBreach() {
        const password = passwordField.value;
        if (!password) {
            Swal.fire('Error', 'Please generate a password first', 'error');
            return;
        }
        
        const breachResult = document.getElementById('breach-result');
        const breachMessage = document.getElementById('breach-message');
        
        // Show loading state
        breachResult.classList.remove('hidden', 'breached', 'safe');
        breachMessage.textContent = 'Checking password against common breaches...';
        
        try {
            // Simulate delay for realistic UX
            await new Promise(resolve => setTimeout(resolve, 300));
            
            // Check against our offline database
            const isBreached = commonPasswords.has(password);
            
            if (isBreached) {
                breachResult.classList.add('breached');
                breachMessage.textContent = 'This password is among the most commonly breached. DO NOT USE IT!';
            } else {
                breachResult.classList.add('safe');
                breachMessage.textContent = 'This password is not in our common breaches database.';
            }
            
            breachResult.classList.remove('hidden');
        } catch (error) {
            console.error('Error checking breach:', error);
            Swal.fire('Error', 'Failed to check password against breaches', 'error');
        }
    }
    
    function saveToVault() {
        const password = passwordField.value;
        if (!password) {
            Swal.fire('Error', 'Please generate a password first', 'error');
            return;
        }
        
        // Switch to vault tab
        document.querySelector('[data-tab="vault"]').click();
        
        // Pre-fill the password field in the vault
        document.getElementById('vault-password').value = password;
    }
    
    // Password Vault functionality
    const unlockBtn = document.getElementById('unlock-btn');
    const lockBtn = document.getElementById('lock-btn');
    const masterPasswordInput = document.getElementById('master-password');
    const vaultContent = document.getElementById('vault-content');
    const addPasswordBtn = document.getElementById('add-password-btn');
    const passwordList = document.getElementById('password-list');
    
    unlockBtn.addEventListener('click', unlockVault);
    lockBtn.addEventListener('click', lockVault);
    addPasswordBtn.addEventListener('click', addPassword);
    
    // Check if vault exists in localStorage
    if (localStorage.getItem('passwordVault')) {
        masterPasswordInput.placeholder = 'Enter Master Password to Unlock';
    }
    
    async function unlockVault() {
        const masterPassword = masterPasswordInput.value;
        if (!masterPassword) {
            Swal.fire('Error', 'Please enter a master password', 'error');
            return;
        }
        
        const encryptedVault = localStorage.getItem('passwordVault');
        
        if (!encryptedVault) {
            // First time user - create new vault
            await createNewVault(masterPassword);
            return;
        }
        
        try {
            // Decrypt the vault with better error handling
            const decryptedVault = await decryptVault(encryptedVault, masterPassword);
            
            // Parse and validate the decrypted data
            const passwords = JSON.parse(decryptedVault);
            if (!Array.isArray(passwords)) {
                throw new Error('Decrypted data is not a valid array');
            }
            
            // Display passwords
            displayPasswords(passwords);
            
            // Show vault content
            unlockBtn.classList.add('hidden');
            lockBtn.classList.remove('hidden');
            vaultContent.classList.remove('hidden');
        } catch (error) {
            console.error('Failed to unlock vault:', error);
            Swal.fire('Error', 'Incorrect master password or corrupted vault', 'error');
            // Clear the master password field for security
            masterPasswordInput.value = '';
        }
    }
    
    async function createNewVault(masterPassword) {
        const { isConfirmed } = await Swal.fire({
            title: 'No existing vault found',
            text: 'Create a new one?',
            icon: 'question',
            showCancelButton: true,
            confirmButtonText: 'Yes',
            cancelButtonText: 'No'
        });
        
        if (isConfirmed) {
            try {
                // Create empty vault
                const emptyVault = JSON.stringify([]);
                const encryptedVault = await encryptVault(emptyVault, masterPassword);
                localStorage.setItem('passwordVault', encryptedVault);
                
                // Show empty vault
                displayPasswords([]);
                
                // Show vault content
                unlockBtn.classList.add('hidden');
                lockBtn.classList.remove('hidden');
                vaultContent.classList.remove('hidden');
                
                Swal.fire('Success', 'New vault created successfully', 'success');
            } catch (error) {
                console.error('Error creating new vault:', error);
                Swal.fire('Error', 'Failed to create new vault', 'error');
            }
        }
    }
    
    function lockVault() {
        // Clear the password list
        passwordList.innerHTML = '';
        
        // Clear the master password field
        masterPasswordInput.value = '';
        
        // Hide vault content
        unlockBtn.classList.remove('hidden');
        lockBtn.classList.add('hidden');
        vaultContent.classList.add('hidden');
        
        // Clear any pending clipboard timeouts
        clipboardTimeouts.forEach((timeoutId, key) => {
            clearTimeout(timeoutId);
            clipboardTimeouts.delete(key);
        });
    }
    
    async function addPassword() {
        const site = document.getElementById('site-name').value;
        const username = document.getElementById('username').value;
        const password = document.getElementById('vault-password').value;
        
        if (!site || !username || !password) {
            Swal.fire('Error', 'Please fill in all fields', 'error');
            return;
        }
        
        // Get current passwords
        const encryptedVault = localStorage.getItem('passwordVault');
        const masterPassword = masterPasswordInput.value;
        
        if (!encryptedVault || !masterPassword) {
            Swal.fire('Error', 'Vault is locked or corrupted', 'error');
            return;
        }
        
        try {
            // Decrypt the vault
            const decryptedVault = await decryptVault(encryptedVault, masterPassword);
            const passwords = JSON.parse(decryptedVault);
            
            // Add new password
            passwords.push({
                site,
                username,
                password
            });
            
            // Encrypt and save the updated vault
            const updatedVault = JSON.stringify(passwords);
            const newEncryptedVault = await encryptVault(updatedVault, masterPassword);
            localStorage.setItem('passwordVault', newEncryptedVault);
            
            // Update the display
            displayPasswords(passwords);
            
            // Clear the input fields
            document.getElementById('site-name').value = '';
            document.getElementById('username').value = '';
            document.getElementById('vault-password').value = '';
            
            Swal.fire('Success', 'Password added to vault', 'success');
        } catch (error) {
            console.error('Failed to add password:', error);
            Swal.fire('Error', 'Failed to add password to vault', 'error');
        }
    }
    
    function displayPasswords(passwords) {
        passwordList.innerHTML = '';
        
        if (passwords.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = '<td colspan="4" style="text-align: center;">No passwords stored yet</td>';
            passwordList.appendChild(row);
            return;
        }
        
        passwords.forEach((item, index) => {
            const row = document.createElement('tr');
            
            row.innerHTML = `
                <td>${escapeHtml(item.site)}</td>
                <td>${escapeHtml(item.username)}</td>
                <td class="password-cell">
                    <span class="hidden-password">••••••••</span>
                    <span class="visible-password" style="display: none;">${escapeHtml(item.password)}</span>
                </td>
                <td>
                    <button class="action-btn show-btn" data-index="${index}">Show</button>
                    <button class="action-btn copy-btn" data-password="${escapeHtml(item.password)}">Copy</button>
                    <button class="action-btn delete-btn" data-index="${index}">Delete</button>
                </td>
            `;
            
            passwordList.appendChild(row);
        });
        
        // Add event listeners for the buttons
        document.querySelectorAll('.show-btn').forEach(btn => {
            btn.addEventListener('click', togglePasswordVisibility);
        });
    
        document.querySelectorAll('.copy-btn').forEach(btn => {
            btn.addEventListener('click', copyVaultPassword);
        });
    
        document.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', deletePassword);
        });
    }
    
    function togglePasswordVisibility(e) {
        const row = e.target.closest('tr');
        const hiddenPassword = row.querySelector('.hidden-password');
        const visiblePassword = row.querySelector('.visible-password');
        const showBtn = row.querySelector('.show-btn');
    
        if (visiblePassword.style.display === 'none') {
            visiblePassword.style.display = 'inline';
            hiddenPassword.style.display = 'none';
            showBtn.textContent = 'Hide';
        } else {
            visiblePassword.style.display = 'none';
            hiddenPassword.style.display = 'inline';
            showBtn.textContent = 'Show';
        }
    }
    
    async function copyVaultPassword(e) {
        const password = e.target.getAttribute('data-password');
        
        try {
            await navigator.clipboard.writeText(password);
            Swal.fire({
                title: 'Copied!',
                text: 'Password copied to clipboard. It will be cleared in 10 seconds.',
                icon: 'success',
                timer: 2000
            });
            
            // Store timeout ID so we can clear it if needed
            const timeoutId = setTimeout(() => {
                clearClipboardSafely('vault-password');
                clipboardTimeouts.delete('vault-password');
            }, 10000);
            
            clipboardTimeouts.set('vault-password', timeoutId);
        } catch (err) {
            console.error('Failed to copy password:', err);
            Swal.fire('Error', 'Failed to copy password', 'error');
        }
    }
    
    async function deletePassword(e) {
        const { isConfirmed } = await Swal.fire({
            title: 'Are you sure?',
            text: 'You won\'t be able to recover this password!',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonText: 'Yes, delete it!',
            cancelButtonText: 'Cancel'
        });
        
        if (!isConfirmed) return;
        
        const index = e.target.getAttribute('data-index');
        const encryptedVault = localStorage.getItem('passwordVault');
        const masterPassword = masterPasswordInput.value;
        
        try {
            // Decrypt the vault
            const decryptedVault = await decryptVault(encryptedVault, masterPassword);
            const passwords = JSON.parse(decryptedVault);
            
            // Remove the password
            passwords.splice(index, 1);
            
            // Encrypt and save the updated vault
            const updatedVault = JSON.stringify(passwords);
            const newEncryptedVault = await encryptVault(updatedVault, masterPassword);
            localStorage.setItem('passwordVault', newEncryptedVault);
            
            // Update the display
            displayPasswords(passwords);
            
            Swal.fire('Deleted!', 'Password has been deleted.', 'success');
        } catch (error) {
            console.error('Failed to delete password:', error);
            Swal.fire('Error', 'Failed to delete password', 'error');
        }
    }
    
    async function deriveKey(masterPassword, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(masterPassword),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
    
        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }
    
    async function encryptVault(data, masterPassword) {
        const encoder = new TextEncoder();
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
    
        const key = await deriveKey(masterPassword, salt);
    
        const encrypted = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            encoder.encode(data)
        );
    
        // Combine salt + iv + encrypted data
        const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
        combined.set(salt, 0);
        combined.set(iv, salt.length);
        combined.set(new Uint8Array(encrypted), salt.length + iv.length);
    
        // Convert to base64 for storage
        return btoa(String.fromCharCode(...combined));
    }
    
    async function decryptVault(encryptedData, masterPassword) {
        try {
            // Convert base64 to Uint8Array
            const binaryString = atob(encryptedData);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
    
            // Extract components
            const salt = bytes.slice(0, 16);
            const iv = bytes.slice(16, 28);
            const data = bytes.slice(28);
    
            // Derive key
            const key = await deriveKey(masterPassword, salt);
    
            // Decrypt
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                key,
                data
            );
    
            return new TextDecoder().decode(decrypted);
        } catch (error) {
            console.error('Decryption failed:', error);
            throw new Error('Failed to decrypt vault - possibly wrong password');
        }
    }
    
    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Remove the duplicate event listener from index.html
    // All delete functionality is now handled within script.js
});

async function checkPasswordBreach(password) {
    const sha1 = await sha1Hash(password);
    const prefix = sha1.substring(0, 5);
    const suffix = sha1.substring(5).toUpperCase();

    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    const text = await response.text();
    const lines = text.split('\n');

    for (let line of lines) {
        const [hashSuffix, count] = line.trim().split(':');
        if (hashSuffix === suffix) {
            return parseInt(count, 10); // breached
        }
    }
    return 0; // safe
}

async function sha1Hash(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function handlePasswordCheck(password) {
    const count = await checkPasswordBreach(password);
    if (count > 0) {
        alert(`⚠️ This password has been found in ${count} breaches! Consider using a stronger one.`);
    } else {
        alert("✅ This password has not been found in any known breaches.");
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const deepCheckBtn = document.querySelector(".special-btn");

    deepCheckBtn.addEventListener("click", async () => {
        const password = document.getElementById("password").value.trim();
        if (!password) {
            Swal.fire("No password", "Please generate or enter a password first.", "warning");
            return;
        }

        const count = await checkPasswordBreach(password);
        if (count > 0) {
            Swal.fire("⚠️ Breach Found", `This password has appeared in ${count} known breaches.`, "error");
        } else {
            Swal.fire("✅ Safe Password", "This password has not been found in any known breaches.", "success");
        }
    });
});
