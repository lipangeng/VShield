(function () {
  function setMsg(text) {
    document.getElementById("msg").textContent = text;
  }

  function readIdentity() {
    var user = "";
    try {
      user = document.cookie.split(";").map(function (v) { return v.trim(); }).find(function (v) { return v.indexOf("_oauth2_proxy=") === 0; }) ? "oauth2-user" : "authenticated";
    } catch (e) {
      user = "authenticated";
    }
    document.getElementById("identity").textContent = "当前已登录，可直接注册当前来源 IP。";
    return user;
  }

  async function call(path) {
    const res = await fetch(path, { credentials: "same-origin" });
    const text = await res.text();
    setMsg("[" + res.status + "] " + text);
  }

  readIdentity();
  document.getElementById("registerBtn").onclick = function () { call("/register"); };
  document.getElementById("cancelBtn").onclick = function () { call("/cancel"); };
})();
