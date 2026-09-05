(function(){
  var M="EXTJS_Q7";
  console.log(M+"_RAN origin="+location.origin+" href="+location.href);
  function up(u){ return fetch(u,{mode:'no-cors',cache:'no-store'})
    .then(function(){console.log(M+"_UP "+u);})
    .catch(function(e){console.log(M+"_DOWN "+u+" "+e.name+":"+e.message);}); }
  (async function(){
    var urls=["http://127.0.0.1:8000/","http://127.0.0.1:9000/",
      "http://127.0.0.1:8000/api/mcp/bootstrap","http://127.0.0.1:8000/internal/preview/error?message=x",
      "http://127.0.0.1:9000/flag","http://127.0.0.1:8000/flag","http://localhost:9000/"];
    for(var i=0;i<urls.length;i++){ await up(urls[i]); }
    console.log(M+"_DONE");
  })();
})();
