const API = {
    endpoint: "/auth/",
    login: async (user) =>{
        return await API.makePostRequest(API.endpoint + "login", user);
    },
    checkAuthOptions: async (data) => {
        return await API.makePostRequest(API.endpoint + "auth-options", data);
    },
    loginFromGoogle: async (user) => {
        return await API.makePostRequest(API.endpoint + "login-google", user);
    },
    register: async (user) =>{
        return await API.makePostRequest(API.endpoint + "register", user);
    },
    webAuthn: {
        loginOptions: async (email) => {
            return await API.makePostRequest(API.endpoint + "webauth-login-options", { email });
        },
        loginVerification: async (email, data) => {
            return await API.makePostRequest(API.endpoint + "webauth-login-verification", {
                email,
                data
            });
        },
        registrationOptions: async () => {
            return await API.makePostRequest(API.endpoint + "webauth-registration-options", Auth.account);
        },
        registrationVerification: async (data) => {
            return await API.makePostRequest(API.endpoint + "webauth-registration-verification", {
                user: Auth.account,
                data
            });
        }
    },

    makePostRequest: async (url, data) => {
        const response = await fetch(url, {
            method: "POST",
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        return await response.json();
    }

}

export default API;
