const CLIENT_ID = '{{.env.GOOGLE_CLIENT_ID}}';

function getProfile() {
    const data = localStorage.getItem('profile');
    return data ? JSON.parse(data) : null;
}

function setProfile(profile) {
    localStorage.setItem('profile', JSON.stringify(profile));
}

export function logout() {
    localStorage.removeItem('profile');
    location.reload();
}

function bind(data) {
    document.querySelectorAll('[data-bind]').forEach(el => {
        const key = el.dataset.bind;
        const value = key.split('.').reduce((o, k) => o?.[k], data);
        if (el.tagName === 'IMG') {
            el.src = value;
        } else {
            el.textContent = value;
        }
    });
}

function waitForGoogle() {
    return new Promise((resolve) => {
        if (typeof google !== 'undefined') {
            resolve();
            return;
        }
        const check = setInterval(() => {
            if (typeof google !== 'undefined') {
                clearInterval(check);
                resolve();
            }
        }, 50);
    });
}

export async function auth() {
    let profile = getProfile();
    if (profile) {
        bind(profile);
        return profile;
    }

    await waitForGoogle();

    const signin = document.getElementById('signin');
    signin.style.display = 'block';
    document.body.style.opacity = 1;

    profile = await new Promise((resolve) => {
        google.accounts.id.initialize({
            client_id: CLIENT_ID,
            callback: async (response) => {
                const res = await fetch('/auth/google/callback', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: 'credential=' + encodeURIComponent(response.credential)
                });
                const profile = await res.json();
                setProfile(profile);
                signin.style.display = 'none';
                resolve(profile);
            }
        });

        google.accounts.id.renderButton(signin, {
            type: 'standard',
            size: 'large',
            theme: 'outline',
            text: 'sign_in_with',
            shape: 'rectangular',
            logo_alignment: 'left'
        });
    });

    bind(profile);
    return profile;
}
