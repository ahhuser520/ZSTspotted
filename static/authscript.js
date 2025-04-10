import { encrypt, decrypt, hashSHA256, sendJsonRequest, hashPassword, url, setSecureCookie, setSecureData, generateRandomString, hash } from './utils.js';

const errMsg1 = document.getElementById("errMsg1");
const errMsg2 = document.getElementById("error2");
let usernameInput = document.getElementById("username");
let passwordInput = document.getElementById("password");
usernameInput.addEventListener('input', function(){
  if(usernameInput.value.length < 5){
    usernameInput.style.border = "1px red solid";
  }else{
    usernameInput.style.border = "1px black solid";
  }
});
passwordInput.addEventListener('input', function(){
  if(passwordInput.value.length < 8){
    passwordInput.style.border = "1px red solid";
  }else{
    passwordInput.style.border = "1px black solid";
  }
});

function showError(error, errorBox){
  if (!isNaN(error) && !isNaN(errorBox)) {
    let errorMessage = "";
    if(error == 429){
      errorMessage = "Please slow down. The server can handle only up to 3 requests per computer per minute.<br />Error code: 429 (TOO MANY REQUESTS)";
    }else if(error == 400){
      console.log("authScript.js, showError(), Invalid data has been sent. Please update your application or reinstall it. Code: 400");
      errorMessage = "Error code: 400. (Invalid or malformed client request)";
    }else if(error == 500){ 
      console.log("authScript.js, showError(), Internal server error. <br />Error code: 500.");
      errorMessage = "Error code: 500. (Internal server error)";
    }else if(error == 401){
      errorMessage = "Password or username incorrect. Try again.<br />Error code: 401 (ACCESS DENIED)";
      console.log("authScript.js, showError(), invalid login data. User has not been found. Error code: 401 (ACCESS DENIED)");
    }else if(error == 409){
      errorMessage = "Critical error found.<br />Error code: 409 (Conflict)";
      console.log("authScript.js, showError(), Error code: 409 (Duplicate records found, Conflict error)");
    }else{
      errorMessage = "Error code: "+error;
    }
    if(errorBox == 2){
      errMsg2.innerHTML = errorMessage;
    }else if(errorBox == 1){
      errMsg1.innerHTML = errorMessage;
    }
  } else {
      console.log("An unexpected error occurred: " + JSON.stringify(error));
  }
}

async function login(){
  let isOkay = true;
  let errorMessage = "";
  var username = document.getElementById("username").value;
  var password = document.getElementById("password").value;
  if (username.length < 5 && password.length < 8){
      //alert("Username or password are too short.");
      console.log("loginScript.js, login(), username and password inputs are too short.")
      errorMessage = "Username and password are too short.";
      isOkay = false;
  }else if(username.length < 5){
      console.log("loginScript.js, login(), username input is too short.");
      errorMessage = "Username is too short.";
      isOkay = false;
  }else if(password.length < 8){
      console.log("loginScript.js, login(), password input is too short.");
      errorMessage = "Password is too short.";
      isOkay = false;
  }else if(username.length > 256 && password.length > 256){
    console.log("loginScript.js, login(), username and password input are too long.");
    errorMessage = "Username and password are too long.";
    isOkay = false;
  }else if(password.length > 256){
    console.log("loginScript.js, login(), password input is too long.");
    errorMessage = "Password is too long.";
    isOkay = false;
  }else if(username.length > 256){
    console.log("loginScript.js, login(), username input is too long.");
    errorMessage = "Username is too long.";
    isOkay = false;
  }else{
      console.log("loginScript.js, login(), password and username lenghts are OK.");
      errorMessage = "";
      isOkay = true;
  }
  if(!isOkay){
    errMsg1.textContent = errorMessage;
    console.log("loginScript.js, login(), Input login data length were not OK.");
  }else{
    try{
      console.log("loginScript.js, login(), Input login data length are OK. Proccesing login script...");
      usernameInput.style.border = "1px black solid";
      passwordInput.style.border = "1px black solid";
      //Form validation succeeded, proceed with the login system algorithm here.
      errMsg1.textContent = "";
      let row = 0;
      let salt = "";
      let hashedLogin = await hash(username);
      console.log("loginScript.js, login(), Hashed login: "+hashedLogin);
      let encryptionKeyFromPassword = await hashSHA256(password);
      console.log("loginScript.js, login(), Hashing password SHA256 to get encryptionKeyFromPassword: "+encryptionKeyFromPassword);
      const data = {
          username: hashedLogin,
        };
        console.log("loginScript.js, login(), Sending JSON data: "+data+", to server: "+url+"getSalt");
        const response = await sendJsonRequest(url+"getSalt", data);
        if (!response.ok) {
          throw new Error(response.status);
        }else{
            const responseData = await response.json();
            console.log('Server response:', responseData);
            salt = responseData.salt;
            const hashedPassword = await hashPassword(password, salt);
            const data1 = {
                username: hashedLogin,
                password: hashedPassword,
              };
            console.log("Sending JSON data: "+data1+", to server api: "+url+"login");
            const response2 = await sendJsonRequest(url+"login", data1);
            if (!response2.ok) {
              throw new Error(response2.status);
            }else{
              const responseData2 = await response2.json();
              console.log('authScript.js, login(), Server response: ', responseData2);
                  let rowString = String(responseData2.row);
                  console.log("authScript.js, login(), Server response, rowString: "+rowString);
                  row = parseInt(rowString);

                  if (isNaN(row)) {
                      console.log("authScript.js, login(), Client got invalid server response: "+rowString);
                      errMsg1.textContent = "Client got invalid server response: "+rowString;
                  }else{
                    let token = String(responseData2.token);
                    if (row == 1){
                        // Authenticated
                        console.log("authScript.js, login(), User data were good and server let log in. User has been auth.");
                        //saveSecureData({ trueEncryptionKey: String(trueEncryptionKey), encryptionKeyFromPassword: encryptionKeyFromPassword, token: String(token), username: String(username), socialSecureKey: String(SocialSecurityKey) });
                        setSecureData("username", username);
                        setSecureCookie("jwt_token", token, "30");
                        location.reload();
                    }else{
                      console.log("authScript.js, login(), Invalid server response: "+rowString);
                      errMsg1.textContent = "Error: Invalid server response. Please update your application or reinstall it.";
                    }
                  }
            }
        }
      }catch(error){
          console.error(error);
          showError(error.message, 1);
      }
  }
}

async function register(){
  let usernameRegister1 = document.getElementById("usernameRegister1");
  let passwordRegister1 = document.getElementById("passwordRegister1");
  let passwordRegister2 = document.getElementById("passwordRegister2");
  let personalData = document.getElementById("personalData");
  let policyPrivacyAgreemenet = document.getElementById("policyPrivacyAgreemenet");
  const captchaToken = document.getElementsByName("cf-turnstile-response")[0].value;
  let errorMsg = "";
  let isOkay = true;
  if(passwordRegister1.value != passwordRegister2.value){
    console.log("authScript.js, register(), passwords inputs are not the same.");
      errorMsg = "Hasła nie są takie same.";
      isOkay = false;
  }
  if(passwordRegister1.value.length < 8){
    console.log("authScript.js, register(), passwords inputs are too short.");
      errorMsg = "Hasła są za krótkie.";
      isOkay = false;
  }
  if(personalData.value.length > 100){
    errorMsg = "Maksymalna ilość znaków to 100.";
    isOkay = false;
  }
  if(!policyPrivacyAgreemenet.checked){
    errorMsg = "Musisz zaakceptować politykę prywatności.";
    isOkay = false;
  }
  if(!isOkay){
      console.log("authScript.js, register(), Register input data were NOT OK.");
      errMsg2.innerHTML = errorMsg;
  }else{
    try{
      console.log("authScript.js, register(), Register input data are OK.");
      errMsg2.innerHTML = "";
      //Form validation succeeded, register alghoritm here:
      const passwordText = passwordRegister1.value;
      const usernameText = usernameRegister1.value;
      const encryptionKeyFromPassword = await hashSHA256(passwordText);
      const salt = generateRandomString(16);
      const saltedPassword = await hashPassword(passwordText, salt);
      const hashedLogin = await hash(usernameText);
      const data = {
        username: hashedLogin,
        password: saltedPassword,
        salt: salt,
        personalData: personalData.value,
        policyPrivacyAgr: String(policyPrivacyAgreemenet.checked),
        'cf-turnstile-response': captchaToken
      };
      console.log("authScript.js, register(), Sending JSON data: "+data+", to server: "+url+"register");
      const response = await sendJsonRequest(url+"register", data);
      if(!response.ok){
        if(response.status == 405){
          document.getElementById("error2").textContent = "Potwierdz, ze nie jesteś robotem.";
        }
        throw new Error(response.status);
      }else{
        const responseData = await response.json();
        console.log("authScript.js, register(), Response data:", responseData);
        if(responseData.success){
            if(responseData.success == "no"){
              console.log("authScript.js, register(), User with provided username already exists.");
              errMsg2.textContent = "User with provided username already exists.";
            }else if(responseData.success == "yes"){
              // Authenticated
              console.log("authScript.js, register(), Register data were good. User has been successfully registered in.");
              const token = responseData.token;
                  console.log("authScript.js, register(), Register data were good. User has been successfully registered in.");
                  setSecureData("username", usernameText);
                  setSecureCookie("jwt_token", token, "30");
                  location.reload();
              //saveSecureData({ encryptionKeyFromPassword: String(encryptionKeyFromPassword), trueEncryptionKey: String(encryptionKeyFromPassword), token: String(token), username: String(usernameText), socialSecureKey: String(SocialSecurityKey) });
              //window.api.send('go-main');
            }else{
              console.log("authScript.js, register(), Invalid data have been recived in response from server.");
              errMsg2.textContent = "Error: response data from server are invalid.";
            }
          }else{
            console.log("authScript.js, register(), Invalid data have been recived in response from server.");
            errMsg2.textContent = "Error: response data from server are invalid.";
          }
      }
    }catch(error){
      console.error(error);
      showError(error.message, 2);
    }
  }     
}
let isLoginDivVisible = false;
function changeLoginAndRegister() {
  const login = document.getElementById("loginDiv");
  const register = document.getElementById("registerDiv");

  // Toggle visibility of login and register forms
  if (login.style.display === "none") {
      login.style.display = "block"; // Show login
      register.style.display = "none"; // Hide register
  } else {
      login.style.display = "none"; // Hide login
      register.style.display = "block"; // Show register
  }
}


/*function register(){
  let usernameRegister1 = document.getElementById("usernameRegister1");
  let usernameRegister2 = document.getElementById("usernameRegister2");
  let passwordRegister1 = document.getElementById("passwordRegister1");
  let passwordRegister2 = document.getElementById("passwordRegister2");
  let errorMsg = "";
  let isOkay = true;
  if (usernameRegister1.value != usernameRegister2.value){
      console.log("authScript.js, register(), username inputs are not the same.");
      errorMsg = "Usernames are not the same.";
      isOkay = false;
  }else if(passwordRegister1.value != passwordRegister2.value){
    console.log("authScript.js, register(), password inputs are not the same.");
      errorMsg = "Passwords are not the same.";
      isOkay = false;
  }
  if(usernameRegister1.value != usernameRegister2.value && passwordRegister1.value != passwordRegister2.value){
    console.log("authScript.js, register(),, username and password inputs are not the same.");
      errorMsg = "Usernames and password are not the same.";
      isOkay = false;
  }
  if(usernameRegister1.value.length < 5 || passwordRegister2.value.length < 8){
    console.log("authScript.js, register(), invalid length of password or username.");
      errorMsg = "The minimum length of username is 5 characters, and 8 for password.";
      isOkay = false;
  }
  if(!isOkay){
      console.log("authScript.js, register(), Register input data were NOT OK.");
      errMsg2.innerHTML = errorMsg;
  }else{
      console.log("authScript.js, register(), Register input data are OK.");
      errMsg2.innerHTML = "";
      //Form validation succeeded, register alghoritm here:
      const passwordText = passwordRegister1.value;
      const usernameText = usernameRegister1.value;
      const encryptionKey = hashSHA256(passwordText);
      const SocialSecurityKey = generateRandomString(64);
      const encryptedSocialSecurityKey = encrypt(SocialSecurityKey, encryptionKey);
      const salt = generateRandomString(16);
      const saltedPassword = hashPassword(passwordText, salt);
      const hashedLogin = hash(usernameText);
      const data = {
        username: hashedLogin,
        password: saltedPassword,
        socialSecurityKey: encryptedSocialSecurityKey,
        salt: salt,
      };
      console.log("authScript.js, register(), Sending JSON data: "+data+", to server: "+url+"register");
      fetch(url + "register", {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
        })
        .then((response) => {
            if (!response.ok) {
                throw new Error(response.status);
            }
            return response.json();
        })
        .then((responseData) => {
            console.log("authScript.js, register(), Response data:", responseData);
            if(responseData.success){
                if(responseData.success == "no"){
                  console.log("authScript.js, register(), User with provided username already exists.");
                  errMsg2.textContent = "User with provided username already exists.";
                }else if(responseData.success == "yes"){
                  // Authenticated
                  const token = responseData.token;
                  console.log("authScript.js, register(), Register data were good. User has been successfully registered in.");
                  setSecureData("username", usernameText);
                  setSecureCookie("jwt_token", token, "30");
                  setSecureData("encryptionKey", encryptionKey);
                  setSecureData("socialSecurityKey", SocialSecurityKey);
                  location.reload();
                }else{
                  console.log("authScript.js, register(), Invalid data have been recived in response from server.");
                  errMsg2.textContent = "Error: response data from server are invalid.";
                }
              }else{
                console.log("authScript.js, register(), Invalid data have been recived in response from server.");
                errMsg2.textContent = "Error: response data from server are invalid.";
              }
        })
        .catch((error) => {
          console.error(error);
          
          showError(error.message, 2);
        });
        
        } 
  }     */
window.login = login;
window.register = register;
window.changeLoginAndRegister = changeLoginAndRegister;