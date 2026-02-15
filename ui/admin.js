(function () {
  function q(id) { return document.getElementById(id); }

  function esc(v) {
    return String(v || "").replace(/[&<>"']/g, function (s) {
      if (s === "&") return "&amp;";
      if (s === "<") return "&lt;";
      if (s === ">") return "&gt;";
      if (s === '"') return "&quot;";
      return "&#39;";
    });
  }

  async function fetchList() {
    const res = await fetch("/admin/whitelist", { credentials: "same-origin" });
    const data = await res.json();
    q("rows").innerHTML = data.map(function (item) {
      return "<tr><td>" + esc(item.ip) + "</td><td>" + esc(item.expireAt) + "</td><td><button class='warn' data-ip='" + esc(item.ip) + "'>移除</button></td></tr>";
    }).join("");

    Array.prototype.forEach.call(document.querySelectorAll("button[data-ip]"), function (btn) {
      btn.onclick = function () { removeIp(btn.getAttribute("data-ip")); };
    });

    q("msg").textContent = "已加载 " + data.length + " 条记录";
  }

  async function addIp() {
    const ip = q("ip").value.trim();
    const ttl = q("ttl").value.trim();
    if (!ip) {
      q("msg").textContent = "请输入 IP";
      return;
    }
    const qs = "/admin/register?ip=" + encodeURIComponent(ip) + (ttl ? "&timeout=" + encodeURIComponent(ttl) : "");
    const res = await fetch(qs, { credentials: "same-origin" });
    q("msg").textContent = "[" + res.status + "] " + await res.text();
    fetchList();
  }

  async function removeIp(ip) {
    const res = await fetch("/admin/cancel?ip=" + encodeURIComponent(ip), { credentials: "same-origin" });
    q("msg").textContent = "[" + res.status + "] " + await res.text();
    fetchList();
  }

  q("addBtn").onclick = addIp;
  q("refreshBtn").onclick = fetchList;
  fetchList();
})();
