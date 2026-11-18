// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Adds a language menu to the mdBook menu bar. Each language is its own book
// (English at the site root, the others under /<code>/), so the link keeps
// the current page when the target book has it and falls back to the target's
// start page when it does not.
(function () {
  "use strict";

  var LANGS = [
    ["en", "English"],
    ["pt", "Português"],
    ["es", "Español"],
    ["de", "Deutsch"],
    ["fr", "Français"],
  ];
  // Pages that exist only in the English book.
  var ENGLISH_ONLY = ["osp-badging.html", "roadmap.html"];
  var GLOBE =
    '<svg viewBox="0 0 512 512" aria-hidden="true"><path d="M352 256c0 22.2-1.2 43.6-3.3 64H163.3c-2.2-20.4-3.3-41.8-3.3-64s1.2-43.6 3.3-64h185.3c2.2 20.4 3.3 41.8 3.3 64zm28.8-64H503.9c5.3 20.5 8.1 41.9 8.1 64s-2.8 43.5-8.1 64H380.8c2.1-20.6 3.2-42 3.2-64s-1.1-43.4-3.2-64zm112.6-32H376.7c-10-63.9-29.8-117.4-55.3-151.6c78.3 20.7 142 77.5 171.9 151.6zm-149.1 0H167.7c6.1-36.4 15.5-68.6 27-94.7c10.5-23.6 22.2-40.7 33.5-51.5C239.4 3.2 248.7 0 256 0s16.6 3.2 27.8 13.8c11.3 10.8 23 27.9 33.5 51.5c11.6 26 20.9 58.2 27 94.7zm-209 0H18.6C48.6 85.9 112.2 29.1 190.6 8.4C165.1 42.6 145.3 96.1 135.3 160zM8.1 192H131.2c-2.1 20.6-3.2 42-3.2 64s1.1 43.4 3.2 64H8.1C2.8 299.5 0 278.1 0 256s2.8-43.5 8.1-64zM194.7 446.6c-11.6-26-20.9-58.2-27-94.6H344.3c-6.1 36.4-15.5 68.6-27 94.6c-10.5 23.6-22.2 40.7-33.5 51.5C272.6 508.8 263.3 512 256 512s-16.6-3.2-27.8-13.8c-11.3-10.8-23-27.9-33.5-51.5zM135.3 352c10 63.9 29.8 117.4 55.3 151.6C112.2 482.9 48.6 426.1 18.6 352H135.3zm358.1 0c-30 74.1-93.6 130.9-171.9 151.6c25.5-34.2 45.2-87.7 55.3-151.6H493.4z"/></svg>';

  var htmlLang = document.documentElement.lang || "en";
  var current = LANGS.some(function (l) { return l[0] === htmlLang; }) ? htmlLang : "en";

  // path_to_root is set by mdBook before this script runs.
  var bookRoot = new URL(typeof path_to_root === "string" && path_to_root ? path_to_root : "./", location.href).pathname;
  if (!bookRoot.endsWith("/")) bookRoot += "/";
  var siteRoot = current === "en" ? bookRoot : bookRoot.slice(0, -(current.length + 1));
  var page = location.pathname.slice(bookRoot.length);
  if (page === "") page = "index.html";

  function hrefFor(code) {
    var base = siteRoot + (code === "en" ? "" : code + "/");
    var keep = !(code !== "en" && ENGLISH_ONLY.indexOf(page) !== -1);
    return base + (keep ? page + location.hash : "");
  }

  var bar = document.querySelector("#mdbook-menu-bar .right-buttons");
  if (!bar) return;

  var wrap = document.createElement("div");
  wrap.className = "lang-switch";

  var btn = document.createElement("button");
  btn.type = "button";
  btn.setAttribute("aria-haspopup", "true");
  btn.setAttribute("aria-expanded", "false");
  btn.setAttribute("aria-label", "Language");
  btn.title = "Language";
  btn.innerHTML = GLOBE + '<span class="lang-code">' + current.toUpperCase() + "</span>";

  var list = document.createElement("ul");
  list.hidden = true;
  list.setAttribute("aria-label", "Language");
  LANGS.forEach(function (l) {
    var li = document.createElement("li");
    var a = document.createElement("a");
    a.href = hrefFor(l[0]);
    a.lang = l[0];
    a.hreflang = l[0];
    a.textContent = l[1];
    if (l[0] === current) a.setAttribute("aria-current", "true");
    li.appendChild(a);
    list.appendChild(li);
  });

  function setOpen(open) {
    list.hidden = !open;
    btn.setAttribute("aria-expanded", String(open));
  }
  btn.addEventListener("click", function (e) {
    e.stopPropagation();
    setOpen(list.hidden);
  });
  document.addEventListener("click", function (e) {
    if (!wrap.contains(e.target)) setOpen(false);
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && !list.hidden) {
      setOpen(false);
      btn.focus();
    }
  });

  wrap.appendChild(btn);
  wrap.appendChild(list);
  bar.insertBefore(wrap, bar.firstChild);
})();
