import API from "./API.js";
import Router from "./Router.js";

const Auth = {
    isLoggedIn: false,
    account: null,
    loginStep: 1,
    register: async (event) => {
        event.preventDefault();
        const user = {
            name: document.getElementById("register_name").value,
            email: document.getElementById("register_email").value,
            password: document.getElementById("register_password").value,
        }
        const response = await API.register(user);
        Auth.postLogin(response, user);
    },
    login: async (event) => {
        if (event) {
            event.preventDefault();
        }
        const credentials = {
            email: document.getElementById("login_email").value,
            password: document.getElementById("login_password").value,
        }
        const response = await API.login(credentials);
        Auth.postLogin(response, {
            ...credentials,
            name: response.name
        });
    },
    loginFromGoogle: async (data) => {
        // data.credential - JWT
        const response = await API.loginFromGoogle(data);
        Auth.postLogin(response, {
            name: response.name,
            email: response.email
        })
    },
    postLogin: (response, user) => {
        if (response.ok) {
            Auth.isLoggedIn = true;
            Auth.account = user;
            Auth.updateStatus();
            Router.go('/account');
        } else {
            alert(response.message);
        }

        // store credentials to the Credential Management API storage
        if (window.PasswordCredential && user.password) {
            const credentials = new PasswordCredential({
                id: user.email,
                password: user.password,
                name: user.name
            })

            // user may turn off the password manager
            try {
                navigator.credentials.store(credentials);
            } catch (e) {
                console.log(e)
            }
        }

        console.log(Auth.account);
    },
    autoLogin: async () => {
        if (window.PasswordCredential) {
            // get the username and unhashed clear password for login user on page load
            const credentials = await navigator.credentials.get({password: true});
            if (credentials) {
                try {
                    document.getElementById("login_email").value = credentials.id;
                    document.getElementById("login_password").value = credentials.password;
                    Auth.login();
                } catch (e) {
                    console.log(e);
                }
            }
        }
    },
    logout: () => {
        Auth.isLoggedIn = false;
        Auth.account = null;
        Auth.updateStatus();
        Router.go('/');

        // Do not auto login after logout
        if (window.PasswordCredential) {
            navigator.credentials.preventSilentAccess();
        }
    },
    updateStatus: () => {
        if (Auth.isLoggedIn && Auth.account) {
            document.querySelectorAll(".logged_out").forEach(
                e => e.style.display = "none"
            );
            document.querySelectorAll(".logged_in").forEach(
                e => e.style.display = "block"
            );
            document.querySelectorAll(".account_name").forEach(
                e => e.innerHTML = Auth.account.name
            );
            document.querySelectorAll(".account_username").forEach(
                e => e.innerHTML = Auth.account.email
            );

        } else {
            document.querySelectorAll(".logged_out").forEach(
                e => e.style.display = "block"
            );
            document.querySelectorAll(".logged_in").forEach(
                e => e.style.display = "none"
            );

        }
    },    
    init: () => {
        document.getElementById('login_section_password').hidden = true;
        document.getElementById('login_section_webauthn').hidden = true;
    },
}
Auth.updateStatus();
Auth.autoLogin();

export default Auth;

// make it a global object
window.Auth = Auth;
