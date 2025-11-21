(function (window, document, CryptoNotes) {
    "use strict";

    var API_BASE = "/notes/api";
    var selectedStudent = null;

    var RECENT_KEY = "notes_recent_students";  // lagres i localStorage

    function $(id) {
        return document.getElementById(id);
    }

    function setMessage(id, text, kind) {
        var el = $(id);
        if (!el) return;
        el.textContent = text || "";
        el.className = "message";
        if (kind) {
            el.classList.add(kind);
        }
    }

    // --- Local "sist brukte"-lagring (kun i nettleser) ---

    function loadRecentStudents() {
        try {
            var raw = window.localStorage.getItem(RECENT_KEY);
            if (!raw) return [];
            var data = JSON.parse(raw);
            if (!Array.isArray(data)) return [];
            return data;
        } catch (e) {
            console.error("Kunne ikke lese recent students:", e);
            return [];
        }
    }

    function saveRecentStudents(list) {
        try {
            window.localStorage.setItem(RECENT_KEY, JSON.stringify(list));
        } catch (e) {
            console.error("Kunne ikke lagre recent students:", e);
        }
    }

    function updateRecentListUI() {
        var listEl = $("recent-student-list");
        var msgId = "recent-message";
        if (!listEl) return;

        listEl.innerHTML = "";
        setMessage(msgId, "", null);

        var list = loadRecentStudents();
        if (!list.length) {
            setMessage(msgId, "Ingen studenter i historikken ennå.", "info");
            return;
        }

        list.forEach(function (st) {
            var li = document.createElement("li");
            li.textContent = st.stud_nr + (st.graduated ? " (avsluttet)" : "");
            li.classList.add("student-item");
            li.addEventListener("click", function () {
                // Når vi henter fra localStorage, har vi bare id/stud_nr/graduated.
                // Det holder for å sette selectedStudent og starte notatvisning.
                setSelectedStudent(st);
            });
            listEl.appendChild(li);
        });
    }

    function addStudentToRecent(st) {
        if (!st || !st.id) return;

        var list = loadRecentStudents();
        // Fjern hvis allerede i lista
        list = list.filter(function (x) { return x.id !== st.id; });
        // Legg først
        list.unshift({
            id: st.id,
            stud_nr: st.stud_nr,
            graduated: !!st.graduated
        });
        // Maks 10
        if (list.length > 10) {
            list = list.slice(0, 10);
        }
        saveRecentStudents(list);
        updateRecentListUI();
    }

    // --- Logout ---

    function setupLogout() {
        var btn = $("logout-btn");
        if (!btn) return;

        btn.addEventListener("click", function () {
            fetch(API_BASE + "/session/end", {
                method: "POST",
                credentials: "include"
            }).catch(function () {
                // ignorer feil
            }).then(function () {
                window.location.href = "/notes/login.html";
            });
        });
    }

    // --- Ny student ---

    function setupCreateStudent() {
        var form = $("create-student-form");
        if (!form) return;

        form.addEventListener("submit", function (e) {
            e.preventDefault();

            var studNrInput = $("new-studnr");
            var gradInput = $("new-graduated");
            var msgId = "create-student-message";

            setMessage(msgId, "", null);

            var stud_nr = (studNrInput.value || "").trim();
            var graduated = !!gradInput.checked;

            if (!stud_nr) {
                setMessage(msgId, "Studentnummer kan ikke være tomt.", "error");
                return;
            }

            fetch(API_BASE + "/students", {
                method: "POST",
                credentials: "include",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ stud_nr: stud_nr, graduated: graduated })
            }).then(function (resp) {
                return resp.json()
                    .catch(function () { return {}; })
                    .then(function (data) {
                        if (resp.status === 401) {
                            window.location.href = "/notes/login.html";
                            throw new Error("Unauthorized");
                        }
                        if (!resp.ok) {
                            var msg = data.detail || "Kunne ikke opprette student.";
                            throw new Error(msg);
                        }
                        return data;
                    });
            }).then(function (data) {
                setMessage(msgId, "Student " + data.stud_nr + " opprettet (id " + data.id + ").", "success");
                studNrInput.value = "";
                gradInput.checked = false;

                // Lukk details om ønskelig
                var det = $("new-student-details");
                if (det && det.open) {
                    det.open = false;
                }

                // Oppdater søkefelt og trigge søk
                var qInput = $("q");
                if (qInput) {
                    qInput.value = data.stud_nr;
                    var searchForm = $("search-form");
                    if (searchForm) {
                        searchForm.dispatchEvent(new Event("submit"));
                    }
                }
            }).catch(function (err) {
                console.error(err);
                setMessage(msgId, err.message || "Klarte ikke å kontakte tjeneren.", "error");
            });
        });
    }

    // --- Søk etter student ---

    function setupSearchStudents() {
        var form = $("search-form");
        if (!form) return;

        form.addEventListener("submit", function (e) {
            e.preventDefault();

            var q = ($("q").value || "").trim();
            var msgId = "search-message";
            var list = $("student-list");

            setMessage(msgId, "", null);
            if (list) list.innerHTML = "";

            var url = API_BASE + "/students";
            if (q) {
                url += "?q=" + encodeURIComponent(q);
            }

            fetch(url, {
                method: "GET",
                credentials: "include"
            }).then(function (resp) {
                if (resp.status === 401) {
                    window.location.href = "/notes/login.html";
                    throw new Error("Unauthorized");
                }
                if (!resp.ok) {
                    throw new Error("Feil ved henting av studenter.");
                }
                return resp.json();
            }).then(function (data) {
                if (!data || !data.length) {
                    setMessage(msgId, "Ingen studenter funnet.", "info");
                    return;
                }

                data.forEach(function (st) {
                    var li = document.createElement("li");
                    li.textContent = st.stud_nr + (st.graduated ? " (avsluttet)" : "");
                    li.classList.add("student-item");
                    li.addEventListener("click", function () {
                        setSelectedStudent(st);
                    });
                    list.appendChild(li);
                });
            }).catch(function (err) {
                console.error(err);
                setMessage(msgId, err.message || "Klarte ikke å kontakte tjeneren.", "error");
            });
        });
    }

    // --- Velg student ---

    function setSelectedStudent(st) {
        selectedStudent = st;

        var label = $("selected-student-label");
        if (label) {
            label.textContent = st.stud_nr + " (id " + st.id + ")";
        }

        var notesSection = $("notes-section");
        if (notesSection) {
            notesSection.style.display = "block";
        }

        var gradCheckbox = $("selected-student-graduated");
        if (gradCheckbox) {
            gradCheckbox.checked = !!st.graduated;
        }

        setMessage("notes-message", "", null);
        setMessage("create-note-message", "", null);
        setMessage("update-student-message", "", null);

        addStudentToRecent(st);
        loadNotesForSelectedStudent();
    }

    // --- Oppdater graduated-status for valgt student ---

    function setupUpdateStudentGraduated() {
        var btn = $("update-student-graduated-btn");
        if (!btn) return;

        btn.addEventListener("click", function () {
            var msgId = "update-student-message";
            setMessage(msgId, "", null);

            if (!selectedStudent) {
                setMessage(msgId, "Velg en student først.", "error");
                return;
            }

            var gradCheckbox = $("selected-student-graduated");
            var graduated = !!(gradCheckbox && gradCheckbox.checked);

            fetch(API_BASE + "/students/" + selectedStudent.id, {
                method: "PUT",
                credentials: "include",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ graduated: graduated })
            }).then(function (resp) {
                return resp.json()
                    .catch(function () { return {}; })
                    .then(function (data) {
                        if (resp.status === 401) {
                            window.location.href = "/notes/login.html";
                            throw new Error("Unauthorized");
                        }
                        if (!resp.ok) {
                            var msg = data.detail || "Kunne ikke oppdatere student.";
                            throw new Error(msg);
                        }
                        return data;
                    });
            }).then(function (data) {
                selectedStudent.graduated = data.graduated;
                setMessage(msgId, "Status oppdatert.", "success");
                addStudentToRecent(selectedStudent); // oppdatere teksten i "sist brukte"
            }).catch(function (err) {
                console.error(err);
                setMessage(msgId, err.message || "Feil ved oppdatering av status.", "error");
            });
        });
    }

    // --- Hent notater for valgt student ---

    function loadNotesForSelectedStudent() {
        var list = $("notes-list");
        var msgId = "notes-message";

        if (list) list.innerHTML = "";
        setMessage(msgId, "", null);

        if (!selectedStudent) return;

        var url = API_BASE + "/notes/" + selectedStudent.id;

        fetch(url, {
            method: "GET",
            credentials: "include"
        }).then(function (resp) {
            if (resp.status === 401) {
                window.location.href = "/notes/login.html";
                throw new Error("Unauthorized");
            }
            if (!resp.ok) {
                throw new Error("Kunne ikke hente notater.");
            }
            return resp.json();
        }).then(function (data) {
            if (!data || !data.length) {
                setMessage(msgId, "Ingen notater for denne studenten ennå.", "info");
                return;
            }

            data.forEach(function (n) {
                CryptoNotes.decryptNote(n.ciphertext_b64, n.nonce_b64)
                    .then(function (plaintext) {
                        var li = document.createElement("li");
                        li.textContent = "[" + n.created + "] " + plaintext;
                        li.classList.add("note-item");
                        list.appendChild(li);
                    });
            });
        }).catch(function (err) {
            console.error(err);
            setMessage(msgId, err.message || "Klarte ikke å kontakte tjeneren.", "error");
        });
    }

    // --- Nytt notat ---

    function setupCreateNote() {
        var form = $("create-note-form");
        if (!form) return;

        form.addEventListener("submit", function (e) {
            e.preventDefault();

            var msgId = "create-note-message";
            setMessage(msgId, "", null);

            if (!selectedStudent) {
                setMessage(msgId, "Velg en student først.", "error");
                return;
            }

            if (!CryptoNotes.isReady()) {
                setMessage(msgId, "Du må først låse opp med krypteringspassord.", "error");
                return;
            }

            var textarea = $("note-text");
            var plaintext = (textarea.value || "").trim();

            if (!plaintext) {
                setMessage(msgId, "Notatet kan ikke være tomt.", "error");
                return;
            }

            CryptoNotes.encryptNote(plaintext)
                .then(function (enc) {
                    return fetch(API_BASE + "/notes", {
                        method: "POST",
                        credentials: "include",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            student_id: selectedStudent.id,
                            ciphertext_b64: enc.ciphertext_b64,
                            nonce_b64: enc.nonce_b64,
                            encryption_version: 1
                        })
                    });
                })
                .then(function (resp) {
                    return resp.json()
                        .catch(function () { return {}; })
                        .then(function (data) {
                            if (resp.status === 401) {
                                window.location.href = "/notes/login.html";
                                throw new Error("Unauthorized");
                            }
                            if (!resp.ok) {
                                var msg = data.detail || "Kunne ikke lagre notat.";
                                throw new Error(msg);
                            }
                            return data;
                        });
                })
                .then(function () {
                    setMessage(msgId, "Notat lagret.", "success");
                    textarea.value = "";
                    loadNotesForSelectedStudent();
                })
                .catch(function (err) {
                    console.error(err);
                    setMessage(msgId, err.message || "Feil under kryptering eller lagring.", "error");
                });
        });
    }

    // --- Krypteringspassord-form ---

    function setupCryptoForm() {
        var form = $("crypto-form");
        if (!form) return;

        form.addEventListener("submit", function (e) {
            e.preventDefault();

            var pwInput = $("crypto-password");
            var pw = (pwInput.value || "");
            setMessage("crypto-message", "", null);

            if (!pw) {
                setMessage("crypto-message", "Passord kan ikke være tomt.", "error");
                return;
            }

            CryptoNotes.initWithPassword(pw)
                .then(function () {
                    setMessage("crypto-message", "Kryptering låst opp. Du kan nå lese og skrive notater.", "success");
                    if (selectedStudent) {
                        loadNotesForSelectedStudent();
                    }
                })
                .catch(function (err) {
                    console.error(err);
                    setMessage("crypto-message", err.message || "Klarte ikke å låse opp med dette passordet.", "error");
                });
        });
    }

    // --- Init ---

    function init() {
        setupLogout();
        setupCryptoForm();
        setupCreateStudent();
        setupSearchStudents();
        setupCreateNote();
        setupUpdateStudentGraduated();
        updateRecentListUI();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }

})(window, document, window.CryptoNotes);