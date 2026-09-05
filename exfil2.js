try {
  console.log("JSEXEC_MARKER_ZULU origin=" + location.origin + " href=" + location.href);
  console.log("JSEXEC_COOKIE=" + document.cookie);
  document.title = "JSEXEC_TITLE_" + location.origin;
} catch (e) {
  console.log("JSEXEC_ERR=" + e.message);
}
