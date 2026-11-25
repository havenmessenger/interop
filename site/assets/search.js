// Search across the site's pages: search.json holds one entry per section (page title, heading, link, text), built
// with the site. Matching is by words, every word must appear, and a heading match ranks above a text match.
(function () {
  "use strict";
  var input = document.getElementById("q");
  var list = document.getElementById("results");
  if (!input || !list) return;
  var index = null;
  var loading = null;

  function load() {
    if (index) return Promise.resolve(index);
    if (!loading) {
      loading = fetch("assets/search.json")
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (entries) { index = entries; return index; })
        .catch(function () { index = []; return index; });
    }
    return loading;
  }

  function score(entry, words) {
    var heading = (entry.t + " " + entry.h).toLowerCase();
    var text = entry.x.toLowerCase();
    var total = 0;
    for (var i = 0; i < words.length; i++) {
      var w = words[i];
      if (heading.indexOf(w) !== -1) total += 5;
      else if (text.indexOf(w) !== -1) total += 1;
      else return 0;
    }
    return total;
  }

  function excerpt(text, word) {
    var at = text.toLowerCase().indexOf(word);
    if (at < 0) return text.slice(0, 140);
    var start = Math.max(0, at - 50);
    return (start > 0 ? "…" : "") + text.slice(start, start + 140) + (start + 140 < text.length ? "…" : "");
  }

  function show(query) {
    var words = query.toLowerCase().split(/\s+/).filter(function (w) { return w.length > 1; });
    list.textContent = "";
    if (!words.length) { list.hidden = true; return; }
    load().then(function (entries) {
      var hits = entries
        .map(function (e) { return { e: e, s: score(e, words) }; })
        .filter(function (h) { return h.s > 0; })
        .sort(function (a, b) { return b.s - a.s; })
        .slice(0, 12);
      list.textContent = "";
      if (!hits.length) {
        var none = document.createElement("li");
        none.className = "none";
        none.textContent = "Nothing found.";
        list.appendChild(none);
      }
      hits.forEach(function (h) {
        var li = document.createElement("li");
        var a = document.createElement("a");
        a.href = h.e.u;
        a.textContent = h.e.h === h.e.t ? h.e.t : h.e.h;
        var small = document.createElement("small");
        small.textContent = (h.e.h === h.e.t ? "" : h.e.t + " · ") + excerpt(h.e.x, words[0]);
        a.appendChild(small);
        li.appendChild(a);
        list.appendChild(li);
      });
      list.hidden = false;
    });
  }

  input.addEventListener("focus", load);
  input.addEventListener("input", function () { show(input.value); });
  input.addEventListener("keydown", function (event) {
    var links = list.querySelectorAll("a");
    if (event.key === "Escape") { input.value = ""; show(""); return; }
    if (event.key === "ArrowDown" && links.length) { event.preventDefault(); links[0].focus(); }
    if (event.key === "Enter" && links.length) { window.location.href = links[0].href; }
  });
  list.addEventListener("keydown", function (event) {
    var links = Array.prototype.slice.call(list.querySelectorAll("a"));
    var at = links.indexOf(document.activeElement);
    if (event.key === "ArrowDown" && at < links.length - 1) { event.preventDefault(); links[at + 1].focus(); }
    if (event.key === "ArrowUp") { event.preventDefault(); (at > 0 ? links[at - 1] : input).focus(); }
    if (event.key === "Escape") { input.focus(); }
  });
  document.addEventListener("click", function (event) {
    if (!event.target.closest || !event.target.closest(".search")) list.hidden = true;
  });
})();
