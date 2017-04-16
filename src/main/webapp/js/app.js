//Variable used to share access to the current CSRF token dictionary
//in which KEY is the backend service name and the VALUE is the current CSRF token to use
var CSRF_TOKENS = {};

//Panel of possible HTTP request type and backend services (used for the demo)
var METHODS_SET = ["GET", "POST", "DELETE", "PUT"];
var BACKEND_SERVICES_SET = ["setUser", "setProfile", "updateAccount", "lockAccount", "initBalance", "resetPassword"];

//Send a random request to a backend service for which a CSRF token is mandatory
function sendRequest(){
    //Select a method
    var methodIndex = Math.floor(Math.random() * ((METHODS_SET.length) - 0)) + 0;
    var method = METHODS_SET[methodIndex];
    //Select a backend service
    var backendServiceIndex = Math.floor(Math.random() * ((BACKEND_SERVICES_SET.length) - 0)) + 0;
    var backendService = BACKEND_SERVICES_SET[backendServiceIndex];
    //Prepare asynchronous Ajax request
    var req = new XMLHttpRequest();
    req.open(method, "/backend/" + backendService + "?param=" + new Date().getTime(), true);
    if(CSRF_TOKENS[backendService] != null){
        req.setRequestHeader("X-TOKEN", CSRF_TOKENS[backendService]);
    }
    req.addEventListener("error", function(evt){ console.error("Request meet an error: " + req.statusText) });
    req.addEventListener("abort", function(evt){ console.error("Request aborted: " + req.statusText) });
    req.addEventListener("load", function(evt){
        if (req.readyState === 4 && req.status === 204) {
            CSRF_TOKENS[backendService] = req.getResponseHeader("X-TOKEN");
            var content = document.getElementById("renderingZone").innerHTML;
            content += "<b>CSRF token initialized for the backend service '" + backendService + "'</b><br>";
            document.getElementById("renderingZone").innerHTML = content;
        }else if (req.readyState === 4 && req.status === 200) {
            CSRF_TOKENS[backendService] = req.getResponseHeader("X-TOKEN");
            var data = JSON.parse(req.responseText);
            var item = "<code>Method: " + data.Method +  " - RequestURI: " + data.RequestURI + " - QueryString: " + data.QueryString + "</code><br>";
            var content = document.getElementById("renderingZone").innerHTML;
            content += item;
            document.getElementById("renderingZone").innerHTML = content;
        }
    });
    //Send request
    req.send(null);
}

//Send a request every 1 sec from 4 scheduler
document.getElementById("requestAction").onclick = sendRequest;
setInterval(sendRequest, 1285);
setInterval(sendRequest, 1456);
setInterval(sendRequest, 1148);
setInterval(sendRequest, 1085);