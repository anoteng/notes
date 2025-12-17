/* Minimal service worker.
   Vi gjør IKKE aggressiv caching av HTML/API pga sensitive data.
   Men SW må finnes for at PWA-installasjon skal funke stabilt i Chrome/Edge. */

self.addEventListener("install", (event) => {
    self.skipWaiting();
});

self.addEventListener("activate", (event) => {
    event.waitUntil(self.clients.claim());
});

// Ikke cache API-kall. La nettleser/HTTP håndtere resten normalt.
self.addEventListener("fetch", (event) => {
    const url = new URL(event.request.url);

    // Pass på at /notes/api aldri caches i SW
    if (url.pathname.startsWith("/notes/api/")) {
        return; // default fetch
    }

    // Ellers: default fetch (ingen caching her heller)
    // (Du kan senere legge inn cache av statiske filer hvis du vil.)
});