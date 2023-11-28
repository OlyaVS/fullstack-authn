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

        if (Auth.loginStep === 1) {
            // WebAuthn Login Step 1
            Auth.checkAuthOptions();

        } else {
            // WebAuthn Login Step 2
            const credentials = {
                email: document.getElementById("login_email").value,
                password: document.getElementById("login_password").value,
            }
            const response = await API.login(credentials);
            Auth.postLogin(response, {
                ...credentials,
                name: response.name
            });
        }
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
    checkAuthOptions: async () => {
        const options = await API.checkAuthOptions({
            email: document.getElementById("login_email").value
        });

        console.log(options);

        if (options.password) {
            document.getElementById('login_section_password').hidden = false;
        }

        if (options.webauthn) {
            document.getElementById('login_section_webauthn').hidden = false;
        }
        Auth.challenge = options.challenge;
        Auth.loginStep = 2;
    },
    addWebAuthn: async () => {
        // 1 step - ask server for options
        const options = await API.webAuthn.registrationOptions();
        // add more metadata to that options
        options.authenticatorSelection.residentKey = 'required';
        options.authenticatorSelection.requireResidentKey = true;
        options.extensions = {
            credProps: true,
        };

        // call the authenticator to do the staff with faceid or what ever
        const authRes = await SimpleWebAuthnBrowser.startRegistration(options);

        // 2 - we send this response back to the server to verify registraion
        const verificationRes = await API.webAuthn.registrationVerification(authRes);
        if (verificationRes.ok) {
            alert("You can now login with WebAuthn!");
        } else {
            alert(verificationRes.message)
        }
    },
    webAuthnLogin: async () => {
        const email = document.getElementById("login_email").value;
        // 1 step - get the options from the server
        const options = await API.webAuthn.loginOptions(email);
        // call the API
        const loginRes = await SimpleWebAuthnBrowser.startAuthentication(options);
        // verify
        const verificationRes = await API.webAuthn.loginVerification(email, loginRes);

        if (verificationRes) {
            Auth.postLogin(verificationRes, verificationRes.user);
        } else {
            alert(verificationRes.message)
        }
    }

}
Auth.updateStatus();
Auth.autoLogin();

export default Auth;

// make it a global object
window.Auth = Auth;
