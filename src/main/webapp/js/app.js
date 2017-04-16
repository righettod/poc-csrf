//Variable use to share access to the current CSRF token
var CSRF_TOKEN = null;

//Panel of possible HTTP request type
var METHODS_SET = ["GET", "POST", "DELETE", "PUT"];

//Send a random request to a backend service for which a CSRF token is mandatory
function sendRequest(){
    //Select a method
    var methodIndex = Math.floor(Math.random() * ((METHODS_SET.length-1) - 0)) + 0;
    var method = METHODS_SET[methodIndex];
    //Prepare Ajax request
    var req = new XMLHttpRequest();
    req.open(method, "/backend/" + new Date().getTime(), true);
    if(CSRF_TOKEN != null){
        req.setRequestHeader("X-TOKEN", CSRF_TOKEN);
    }
    req.addEventListener("error", function(evt){ console.error("Request meet an error: " + req.statusText) });
    req.addEventListener("abort", function(evt){ console.error("Request aborted: " + req.statusText) });
    req.addEventListener("load", function(evt){
        console.log(evt);
        if (req.readyState === 4 && req.status === 204 && req.getResponseHeader("X-TOKEN") != null) {
            CSRF_TOKEN = req.getResponseHeader("X-TOKEN");
            var content = document.getElementById("renderingZone").innerHTML;
            content += "<b>CSRF token initialized</b><br>";
            document.getElementById("renderingZone").innerHTML = content;
        }else if (req.readyState === 4 && req.status === 200) {
            var data = JSON.parse(req.responseText);
            var item = "<code>Method: " + data.Method +  " - RequestURI: " + data.RequestURI + " - QueryString: " + data.QueryString + "</code><br>";
            var content = document.getElementById("renderingZone").innerHTML;
            content += item;
            document.getElementById("renderingZone").innerHTML = content;
            CSRF_TOKEN = req.getResponseHeader("X-TOKEN");
        }
    });
    //Send request
    req.send(null);
}

//Send a request every 1 sec
setInterval(sendRequest, 1000);
document.getElementById("requestAction").onclick = sendRequest;