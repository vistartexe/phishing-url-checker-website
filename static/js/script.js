(function () {
    var $ = function (id) {
        return document.getElementById(id);
    };

    // ---- Prediction verdict information
    var VERDICTS = {
        LEGITIMATE: {
            icon: "✔",
            text: "The domain name looks ordinary. This is not a guarantee of safety."
        },
        PHISHING: {
            icon: "⚠",
            text: "The domain name looks like typical phishing. Do not enter any personal data."
        },
        SUSPICIOUS: {
            icon: "⚠",
            text: "The model likes the domain name, but serious red flags are present."
        },
        UNCERTAIN: {
            icon: "?",
            text: "The model cannot decide from the domain name alone. Be careful."
        }
    };


    // ---- Display flag lists
    function fillList(container, items, serious) {
        container.textContent = "";

        if (!items.length) {
            var p = document.createElement("p");
            p.className = "none";
            p.textContent = "None found.";
            container.appendChild(p);
            return;
        }

        var ul = document.createElement("ul");
        ul.className = "flags" + (serious ? " serious" : "");

        items.forEach(function (t) {
            var li = document.createElement("li");
            li.textContent = t;
            ul.appendChild(li);
        });

        container.appendChild(ul);
    }


    // ---- Display error messages
    function showError(msg) {
        $("result").hidden = true;
        $("error").textContent = msg;
        $("error").hidden = false;
    }


    // ---- Display prediction results
    function show(d) {
        var v = VERDICTS[d.verdict];

        $("error").hidden = true;

        $("verdict").className = "verdict v-" + d.verdict;
        $("icon").textContent = v.icon;
        $("vtitle").textContent = d.verdict;
        $("vtext").textContent = v.text;

        var pct = Math.round(d.score * 100);

        $("score").textContent = pct + "%";
        $("tick").style.left = Math.min(Math.max(pct, 1), 99) + "%";

        $("r-url").textContent = d.url;
        $("r-domain").textContent = d.judged_domain;

        fillList($("serious"), d.serious_flags, true);
        fillList($("minor"), d.minor_flags, false);

        $("result").hidden = false;
    }


    // ---- Handle URL submission
    $("form").addEventListener("submit", function (ev) {
        ev.preventDefault();

        var url = $("url").value.trim();

        if (!url) return;

        $("go").disabled = true;
        $("go").textContent = "Checking…";

        fetch("/api/check", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        })
            .then(function (r) {
                return r.json().then(function (j) {
                    return {
                        ok: r.ok,
                        body: j
                    };
                });
            })
            .then(function (res) {
                res.ok
                    ? show(res.body)
                    : showError(res.body.error || "Something went wrong.");
            })
            .catch(function () {
                showError("Could not reach the server. Please try again.");
            })
            .then(function () {
                $("go").disabled = false;
                $("go").textContent = "Check URL";
            });
    });


    // ---- Handle example URL buttons
    Array.prototype.forEach.call(
        document.querySelectorAll(".ex"),
        function (b) {
            b.addEventListener("click", function () {
                $("url").value = b.getAttribute("data-u");
                $("form").requestSubmit();
            });
        }
    );

})();